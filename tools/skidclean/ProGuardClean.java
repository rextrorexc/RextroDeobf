import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * ProGuard (ve benzeri adlandırma-obfuscator) çıktısını bayt kodu seviyesinde okunur hâle getirir:
 *   1. yerel değişken yuvalarını "web" bazında ayırır (ProGuard yuva yeniden kullanımı CFR'ı şaşırtır)
 *   2. mapping.txt verilirse tüm adları birebir geri yükler
 *   3. verilmezse sınıf / alan / metot adlarını koddan türetir (enum sabitleri, istisna mesajları, tür adları, getter/setter ...)
 *
 * java -cp asm*.jar;. ProGuardClean in.jar out.jar [--mapping mapping.txt] [--filter regex]
 */
public class ProGuardClean {
    final Map<String, ClassNode> classes = new LinkedHashMap<>();
    int statSplit, statCls, statFld, statMth, statEnum, statMapped;

    /* ============================================================ 1) yerel değişken ayırma */
    static final class Def extends BasicValue {
        final Set<AbstractInsnNode> defs;
        Def(Type t, Set<AbstractInsnNode> d) { super(t); defs = d; }
        @Override public boolean equals(Object o) { return o instanceof Def x && x.defs.equals(defs) && Objects.equals(getType(), x.getType()); }
        @Override public int hashCode() { return defs.hashCode(); }
    }

    static final class DefInterp extends BasicInterpreter {
        final Map<AbstractInsnNode, Set<AbstractInsnNode>> uses = new IdentityHashMap<>();
        final Map<Integer, LabelNode> paramMarks = new HashMap<>();
        boolean bad = false;
        DefInterp() { super(ASM9); }
        static Type slotType(AbstractInsnNode in) {
            switch (in.getOpcode()) {
                case ISTORE: case ILOAD: case IINC: return Type.INT_TYPE;
                case LSTORE: case LLOAD: return Type.LONG_TYPE;
                case FSTORE: case FLOAD: return Type.FLOAT_TYPE;
                case DSTORE: case DLOAD: return Type.DOUBLE_TYPE;
                default: return Type.getObjectType("java/lang/Object");
            }
        }
        @Override public BasicValue newParameterValue(boolean inst, int local, Type type) {
            BasicValue base = super.newParameterValue(inst, local, type);
            LabelNode mark = new LabelNode();
            paramMarks.put(local, mark);
            return new Def(base.getType(), new HashSet<>(Collections.singleton(mark)));
        }
        @Override public BasicValue copyOperation(AbstractInsnNode in, BasicValue v) throws AnalyzerException {
            int op = in.getOpcode();
            if (op >= ISTORE && op <= ASTORE) return new Def(slotType(in), new HashSet<>(Collections.singleton(in)));
            if (op >= ILOAD && op <= ALOAD) {
                if (v instanceof Def d) uses.put(in, d.defs); else bad = true;
                return v;
            }
            return super.copyOperation(in, v);
        }
        @Override public BasicValue unaryOperation(AbstractInsnNode in, BasicValue v) throws AnalyzerException {
            if (in.getOpcode() == IINC) {
                if (v instanceof Def d) uses.put(in, d.defs); else bad = true;
                return new Def(Type.INT_TYPE, new HashSet<>(Collections.singleton(in)));
            }
            return super.unaryOperation(in, v);
        }
        @Override public BasicValue merge(BasicValue a, BasicValue b) {
            if (a instanceof Def x && b instanceof Def y) {
                if (x.defs.containsAll(y.defs)) return a;
                Set<AbstractInsnNode> u = new HashSet<>(x.defs); u.addAll(y.defs);
                return new Def(x.getType(), u);
            }
            return super.merge(a, b);
        }
    }

    static final class UF {
        final Map<Object, Object> p = new IdentityHashMap<>();
        Object find(Object x) { Object r = x; while (p.get(r) != null && p.get(r) != r) r = p.get(r); if (!p.containsKey(x)) p.put(x, x); Object c = x; while (c != r) { Object n = p.get(c); p.put(c, r); c = n; } return r; }
        void union(Object a, Object b) { Object ra = find(a), rb = find(b); if (ra != rb) p.put(ra, rb); }
    }

    boolean splitLocals(ClassNode cn, MethodNode mn) {
        if (mn.instructions.size() == 0 || (mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) return false;
        DefInterp ip = new DefInterp();
        try { new Analyzer<>(ip).analyze(cn.name, mn); } catch (Exception | StackOverflowError e) { return false; }
        if (ip.bad) return false;
        UF uf = new UF();
        for (var e : ip.uses.entrySet()) {
            Object first = null;
            uf.find(e.getKey());
            for (AbstractInsnNode d : e.getValue()) { uf.find(d); if (first == null) first = d; else uf.union(first, d); }
            if (first != null) uf.union(e.getKey(), first);      // IINC için: kullanım düğümü de web'e girer
        }
        // her yuva için web'ler
        Map<Integer, Map<Object, Integer>> slotWebs = new HashMap<>();     // eski yuva -> (kök -> yeni yuva)
        int next = mn.maxLocals;
        // parametre web'leri eski yuvada kalır
        Map<Object, Integer> assigned = new IdentityHashMap<>();
        for (var pm : ip.paramMarks.entrySet()) assigned.put(uf.find(pm.getValue()), pm.getKey());
        boolean any = false;
        for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
            int op = in.getOpcode();
            boolean store = op >= ISTORE && op <= ASTORE, load = op >= ILOAD && op <= ALOAD, inc = op == IINC;
            if (!store && !load && !inc) continue;
            int var = in instanceof VarInsnNode v ? v.var : ((IincInsnNode) in).var;
            Object root;
            if (store || inc) root = uf.find(in);
            else { Set<AbstractInsnNode> d = ip.uses.get(in); if (d == null || d.isEmpty()) continue; root = uf.find(d.iterator().next()); }
            Integer slot = assigned.get(root);
            if (slot == null) {
                // ilk web özgün yuvada kalır (parametre değilse): aynı yuvada başka web daha önce atanmadıysa
                boolean taken = assigned.containsValue(var) && slotWebs.containsKey(var) ? true : false;
                Map<Object, Integer> m = slotWebs.computeIfAbsent(var, k -> new IdentityHashMap<>());
                boolean origUsed = assigned.containsValue(var);
                if (!origUsed) { slot = var; }
                else { slot = next; next += (op == LSTORE || op == DSTORE || op == LLOAD || op == DLOAD) ? 2 : 1; any = true; }
                assigned.put(root, slot);
            }
            if (slot != var) {
                if (in instanceof VarInsnNode v) v.var = slot; else ((IincInsnNode) in).var = slot;
                any = true;
            }
        }
        if (any) { mn.maxLocals = Math.max(mn.maxLocals, next); mn.localVariables = null; statSplit++; }
        return any;
    }

    /* ============================================================ yardımcılar */
    static final Set<String> JDK_PREFIX = new HashSet<>(Arrays.asList("java/", "javax/", "jdk/", "sun/", "kotlin/"));

    boolean isLib(String internal) { return !classes.containsKey(internal); }

    static boolean obfMember(String n) {
        if (n.equals("<init>") || n.equals("<clinit>")) return false;
        if (n.length() <= 2) return true;
        if (n.matches("[a-z]{1,2}\\d?")) return true;
        if (!validIdent(n)) return true;
        if (n.matches("[IlLi1oO0]{3,}")) return true;
        if (n.matches("(?i)(?:method|field|class|param|var|obj)_?\\d*")) return true;
        if (n.matches("[a-z]{1,4}\\d+[a-z]?") && !n.matches("(?:md5|sha\\d+|utf\\d+|log4j|x509|ipv\\d)")) return true;
        return false;
    }
    static boolean validIdent(String n) {
        if (n.isEmpty() || !Character.isJavaIdentifierStart(n.charAt(0))) return false;
        for (int i = 0; i < n.length(); i++) { char c = n.charAt(i); if (c >= 0x80 || c < 0x20 || !Character.isJavaIdentifierPart(c)) return false; }
        return !isKeyword(n);
    }
    static boolean obfClass(String internal) {
        String s = internal.substring(internal.lastIndexOf('/') + 1);
        if (s.contains("$")) s = s.substring(s.lastIndexOf('$') + 1);
        return s.length() <= 2 || !validIdent(s) || s.matches("[IlLi1oO0]{3,}") || s.matches("(?i)(?:class|interface|enum|method|field)_?\\d*") || s.matches("[a-z]{3,}\\d+[a-z]?") || s.matches("[A-Za-z]\\d?");
    }

    static String pascal(String s) {
        StringBuilder sb = new StringBuilder();
        for (String w : s.split("[^A-Za-z0-9]+")) if (!w.isEmpty()) sb.append(Character.toUpperCase(w.charAt(0))).append(w.substring(1));
        return sb.toString();
    }
    static String lcFirst(String s) { return s.isEmpty() ? s : Character.toLowerCase(s.charAt(0)) + s.substring(1); }
    static String simple(String internal) { String s = internal.substring(internal.lastIndexOf('/') + 1); return s.substring(s.lastIndexOf('$') + 1); }

    /* ============================================================ mapping.txt (ProGuard retrace) */
    Map<String, String> mapCls = new HashMap<>();                 // obf internal -> orijinal internal
    Map<String, String> mapFld = new HashMap<>();                 // obfOwner.name -> orijinal ad
    Map<String, String> mapMth = new HashMap<>();                 // obfOwner.name+desc(obf) -> orijinal ad

    void loadMapping(File f) throws IOException {
        // satır: "orig.Class -> obf.Class:"  /  "    type name -> obf"  /  "    1:2:type m(args) -> obf"
        Map<String, String> origToObf = new HashMap<>();
        List<String[]> clsLines = new ArrayList<>();
        String cur = null;
        List<String[]> members = new ArrayList<>();   // [curObfClass, kind, ...]
        for (String line : java.nio.file.Files.readAllLines(f.toPath())) {
            if (line.startsWith("#") || line.isBlank()) continue;
            if (!line.startsWith(" ")) {
                Matcher m = Pattern.compile("^(\\S+) -> (\\S+):$").matcher(line.trim());
                if (m.find()) { cur = m.group(2).replace('.', '/'); mapCls.put(cur, m.group(1).replace('.', '/')); origToObf.put(m.group(1).replace('.', '/'), cur); }
            } else if (cur != null) {
                String t = line.trim().replaceFirst("^\\d+:\\d+:", "").replaceFirst(":\\d+:\\d+$", "").replaceFirst("^\\d+:\\d+:", "");
                Matcher fm = Pattern.compile("^([\\w.$\\[\\]<>]+) ([\\w$<>]+) -> ([\\w$<>]+)$").matcher(t);
                Matcher mm = Pattern.compile("^([\\w.$\\[\\]<>]+) ([\\w$<>]+)\\(([^)]*)\\)(?::\\d+)? -> ([\\w$<>]+)$").matcher(t);
                if (mm.find()) members.add(new String[]{cur, "m", mm.group(1), mm.group(2), mm.group(3), mm.group(4)});
                else if (fm.find()) members.add(new String[]{cur, "f", fm.group(1), fm.group(2), fm.group(3)});
            }
        }
        for (String[] mb : members) {
            if (mb[1].equals("f")) { if (!mb[3].equals(mb[4])) mapFld.put(mb[0] + "." + mb[4], mb[3]); }
            else {
                // obf imza: tür adlarını obf karşılıklarına çevir
                StringBuilder d = new StringBuilder("(");
                if (!mb[4].isBlank()) for (String a : mb[4].split(",")) d.append(descOf(a.trim(), origToObf));
                d.append(")").append(descOf(mb[2], origToObf));
                if (!mb[3].equals(mb[5]) && !mb[3].startsWith("<")) mapMth.put(mb[0] + "." + mb[5] + d, mb[3]);
            }
        }
    }

    static String descOf(String t, Map<String, String> origToObf) {
        int dims = 0; while (t.endsWith("[]")) { dims++; t = t.substring(0, t.length() - 2); }
        String d;
        switch (t) {
            case "int": d = "I"; break; case "long": d = "J"; break; case "boolean": d = "Z"; break; case "byte": d = "B"; break;
            case "char": d = "C"; break; case "short": d = "S"; break; case "float": d = "F"; break; case "double": d = "D"; break; case "void": d = "V"; break;
            default: { String in = t.replace('.', '/'); d = "L" + origToObf.getOrDefault(in, in) + ";"; }
        }
        return "[".repeat(dims) + d;
    }

    /* ============================================================ adlandırma */
    final Map<String, String> clsNew = new HashMap<>();            // eski internal -> yeni internal
    final Map<String, String> fldNew = new HashMap<>();            // owner.name -> yeni
    final Map<String, String> mthNew = new HashMap<>();            // owner.name+desc -> yeni

    ClassNode superOf(ClassNode c) { return c.superName == null ? null : classes.get(c.superName); }

    /** alanı bildiren sınıfı bul (alt sınıf sahibi ile erişilmiş olabilir) */
    String fieldOwner(String owner, String name, String desc) {
        String o = owner;
        for (int i = 0; i < 20 && o != null; i++) {
            ClassNode c = classes.get(o);
            if (c == null) return null;
            for (FieldNode f : c.fields) if (f.name.equals(name) && f.desc.equals(desc)) return o;
            for (String itf : c.interfaces) { String r = fieldOwner(itf, name, desc); if (r != null) return r; }
            o = c.superName;
        }
        return null;
    }

    Set<String> allSupers(String internal) {
        Set<String> out = new LinkedHashSet<>();
        Deque<String> q = new ArrayDeque<>(); q.add(internal);
        while (!q.isEmpty()) {
            String n = q.poll(); ClassNode c = classes.get(n);
            if (c == null) continue;
            if (c.superName != null && out.add(c.superName)) q.add(c.superName);
            for (String i : c.interfaces) if (out.add(i)) q.add(i);
        }
        return out;
    }

    static List<String> stringsOf(ClassNode c) {
        List<String> out = new ArrayList<>();
        for (MethodNode m : c.methods) for (AbstractInsnNode i : m.instructions) {
            if (i instanceof LdcInsnNode l && l.cst instanceof String s) out.add(s);
            else if (i instanceof InvokeDynamicInsnNode d && d.bsmArgs != null) for (Object o : d.bsmArgs) if (o instanceof String s2) out.add(s2.replace('\u0001', ' ').replace('\u0002', ' '));
        }
        return out;
    }

    static final Set<String> STOPW = new HashSet<>(Arrays.asList("the", "and", "for", "with", "from", "this", "that", "not", "has", "was", "are", "you", "your", "can", "error", "failed", "invalid", "null", "true", "false", "value", "name", "full"));

    static final Set<String> TSTOP = new HashSet<>(Arrays.asList("get", "set", "add", "put", "size", "equals", "hash", "code", "string", "object", "class", "value", "values", "append", "length", "name", "list", "map", "iterator", "next", "has", "remove", "contains", "clear", "index", "char", "builder", "buffer", "integer", "long", "boolean", "double", "float", "array", "arrays", "system", "math", "thread", "exception", "error", "throwable", "runtime", "void", "this", "that", "with", "from", "null", "true", "false", "init", "empty", "copy", "type", "types", "info", "data", "new", "min", "max", "key", "keys", "entry", "entries", "collection", "collections", "objects", "optional", "stream", "format", "print", "println", "message", "text", "line", "lines", "file", "path", "read", "write", "close", "open", "start", "stop", "run", "call", "apply", "accept", "test", "supplier", "function", "consumer", "predicate", "comparable", "comparator", "serializable", "cloneable", "number", "byte", "short", "char", "sequence", "charsequence", "enum", "ordinal", "clone", "finalize", "wait", "notify", "all", "any", "one", "two"));

    Map<String, Map<String, Double>> tokenFeat;
    Map<String, Integer> tokenDf = new HashMap<>();

    static List<String> words(String id) {
        List<String> out = new ArrayList<>();
        for (String w : id.replaceAll("([a-z0-9])([A-Z])", "$1 $2").replaceAll("([A-Z]+)([A-Z][a-z])", "$1 $2").toLowerCase().split("[^a-z]+")) if (w.length() >= 4) out.add(w);
        return out;
    }

    void buildTokens() {
        tokenFeat = new HashMap<>();
        for (ClassNode c : classes.values()) {
            Map<String, Double> f = new HashMap<>();
            Set<String> seenLib = new HashSet<>();
            for (MethodNode m : c.methods) {
                if (!obfMember(m.name) && !m.name.startsWith("<")) for (String w : words(m.name)) f.merge(w, 2.0, Double::sum);
                for (AbstractInsnNode i : m.instructions) {
                    if (i instanceof MethodInsnNode mi) {
                        if (isLib(mi.owner) && !mi.owner.startsWith("[")) {
                            if (!mi.owner.startsWith("java/lang/") && !mi.owner.startsWith("java/util/function/")) for (String w : words(simple(mi.owner))) f.merge(w, seenLib.add(mi.owner) ? 1.0 : 0.2, Double::sum);
                            if (!obfMember(mi.name)) for (String w : words(mi.name)) f.merge(w, 0.4, Double::sum);
                        }
                    } else if (i instanceof FieldInsnNode fi) {
                        if (isLib(fi.owner) && !fi.owner.startsWith("java/lang/")) for (String w : words(simple(fi.owner))) f.merge(w, 0.5, Double::sum);
                        if (isLib(fi.owner) && !obfMember(fi.name)) for (String w : words(fi.name)) f.merge(w, 0.4, Double::sum);
                    } else if (i instanceof TypeInsnNode ti) {
                        if (isLib(ti.desc) && !ti.desc.startsWith("java/lang/") && !ti.desc.startsWith("[")) for (String w : words(simple(ti.desc))) f.merge(w, 0.6, Double::sum);
                    }
                }
            }
            for (FieldNode fn : c.fields) {
                if (!obfMember(fn.name)) for (String w : words(fn.name)) f.merge(w, 2.5, Double::sum);
                Type t = Type.getType(fn.desc);
                if (t.getSort() == Type.OBJECT && isLib(t.getInternalName()) && !t.getInternalName().startsWith("java/lang/")) for (String w : words(simple(t.getInternalName()))) f.merge(w, 1.2, Double::sum);
            }
            for (String s : stringsOf(c)) for (String w : s.split("[^A-Za-z]+")) if (w.length() >= 4) f.merge(w.toLowerCase(), 1.2, Double::sum);
            f.keySet().removeIf(TSTOP::contains);
            tokenFeat.put(c.name, f);
            for (String w : f.keySet()) tokenDf.merge(w, 1, Integer::sum);
        }
    }

    List<String> topTokens(ClassNode c, int k) {
        Map<String, Double> f = tokenFeat.getOrDefault(c.name, Map.of());
        int n = Math.max(1, classes.size());
        List<Map.Entry<String, Double>> es = new ArrayList<>();
        for (var e : f.entrySet()) es.add(Map.entry(e.getKey(), e.getValue() * Math.log(1 + (double) n / tokenDf.getOrDefault(e.getKey(), 1))));
        es.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
        List<String> out = new ArrayList<>();
        for (int i = 0; i < Math.min(k, es.size()); i++) out.add(es.get(i).getKey());
        return out;
    }

    String classNameFor(ClassNode c, Map<String, Integer> counters, Set<String> usedSimple) {
        String simpleOld = simple(c.name);
        List<String> strs = stringsOf(c);
        boolean isEnum = (c.access & ACC_ENUM) != 0;
        boolean isIface = (c.access & ACC_INTERFACE) != 0;
        String sup = c.superName == null ? "" : c.superName;
        String supSimple = simple(sup);
        // SourceFile
        if (c.sourceFile != null && c.sourceFile.endsWith(".java")) {
            String sf = c.sourceFile.substring(0, c.sourceFile.length() - 5);
            if (sf.length() > 2 && !sf.equals(simpleOld) && sf.matches("[A-Za-z_][A-Za-z0-9_]*")) return sf;
        }
        // main sınıfı
        for (MethodNode m : c.methods) if (m.name.equals("main") && m.desc.equals("([Ljava/lang/String;)V")) return "Main";
        // istisna
        String cur = sup; boolean isExc = false;
        for (int i = 0; i < 10 && cur != null && !cur.isEmpty(); i++) {
            if (cur.endsWith("Exception") || cur.endsWith("Error") || cur.equals("java/lang/Throwable")) { isExc = true; break; }
            ClassNode sc = classes.get(cur); cur = sc == null ? null : sc.superName;
        }
        if (isExc) {
            for (String s : strs) {
                String t = s.replaceAll("[^A-Za-z ]+", " ").trim();
                List<String> words = new ArrayList<>();
                for (String w : t.split("\\s+")) if (w.length() > 2 && !STOPW.contains(w.toLowerCase())) words.add(w);
                if (!words.isEmpty() && words.size() <= 4) return pascal(String.join(" ", words)) + "Exception";
            }
            return "CustomException";
        }
        if (isEnum) {
            List<String> consts = new ArrayList<>();
            for (FieldNode f : c.fields) if ((f.access & ACC_ENUM) != 0) consts.add(fldNew.getOrDefault(c.name + "." + f.name, f.name));
            Set<String> cs = new HashSet<>(consts);
            if (cs.contains("FAST") || cs.contains("SLOW")) return "Speed";
            if (cs.contains("LOW") || cs.contains("HIGH") || cs.contains("MEDIUM")) return "Level";
            if (cs.contains("EASY") || cs.contains("HARD")) return "Difficulty";
            if (cs.contains("NORTH") || cs.contains("UP") || cs.contains("DOWN")) return "Direction";
            if (cs.contains("ON") || cs.contains("OFF")) return "Toggle";
            if (cs.contains("RED") || cs.contains("GREEN") || cs.contains("BLUE")) return "Color";
            if (cs.contains("INFO") || cs.contains("WARN") || cs.contains("ERROR") || cs.contains("DEBUG")) return "LogLevel";
            if (cs.contains("GET") || cs.contains("POST")) return "HttpMethod";
            if (cs.contains("CLIENT") || cs.contains("SERVER")) return "Side";
            return "Enum";
        }
        if (isIface) { List<String> t1 = topTokens(c, 1); return t1.isEmpty() ? "Interface" : pascal(t1.get(0)); }
        // belirgin dize sözcükleri
        Map<String, Integer> tok = new HashMap<>();
        for (String s : strs) for (String w : s.split("[^A-Za-z]+")) if (w.length() >= 4 && !STOPW.contains(w.toLowerCase())) tok.merge(w.toLowerCase(), 1, Integer::sum);
        // dahil edilen proje sınıflarına referans
        boolean staticOnly = true; int methods = 0;
        for (MethodNode m : c.methods) { if (m.name.startsWith("<")) continue; methods++; if ((m.access & ACC_STATIC) == 0) staticOnly = false; }
        if (methods > 0 && staticOnly) { List<String> t0 = topTokens(c, 1); return t0.isEmpty() ? "Utils" : pascal(t0.get(0)) + "Utils"; }
        if (!supSimple.isEmpty() && !supSimple.equals("Object") && !obfClass(sup)) {
            String s = supSimple; return (s.startsWith("Abstract") ? s.substring(8) : s) + "Impl";
        }
        for (String itf : c.interfaces) if (!obfClass(itf) && !itf.startsWith("java/lang/")) return simple(itf) + "Impl";
        if (!tok.isEmpty()) { String t = Collections.max(tok.entrySet(), Map.Entry.comparingByValue()).getKey(); return pascal(t); }
        List<String> tops = topTokens(c, 3);
        if (!tops.isEmpty()) {
            String role = staticOnly ? "Utils" : "";
            String base = pascal(tops.get(0));
            if (!role.isEmpty() && !base.endsWith(role)) base += role;
            return base;
        }
        return "Class";
    }

    void computeClassNames() {
        buildTokens();
        Set<String> used = new HashSet<>();
        for (ClassNode c : classes.values()) if (!obfClass(c.name)) used.add(simple(c.name).toLowerCase());
        Map<String, Integer> counters = new HashMap<>();
        for (ClassNode c : classes.values()) {
            if (!obfClass(c.name) || c.name.contains("$") && !obfClass(c.name)) continue;
            if (mapCls.containsKey(c.name)) continue;
            String base = classNameFor(c, counters, used);
            if (base == null) continue;
            if (JAVA_LANG.contains(base) || base.equals("Class") || base.equals("Enum") || base.equals("Interface") || base.equals("Utils") || base.equals("Data")) base = base + "1";
            String pkg = c.name.contains("/") ? c.name.substring(0, c.name.lastIndexOf('/') + 1) : "";
            String outer = c.name.contains("$") ? c.name.substring(0, c.name.lastIndexOf('$') + 1) : null;
            String name = base; int k = 1;
            if (name.matches(".*\\d$") && JAVA_LANG.contains(name.replaceAll("\\d+$", ""))) { }
            while (used.contains((outer != null ? outer : pkg).toLowerCase() + name.toLowerCase()) || used.contains(name.toLowerCase()) && outer == null) { k++; name = (base.matches(".*\\d$") ? base.replaceAll("\\d+$", "") : base) + k; }
            used.add(name.toLowerCase());
            used.add(((outer != null ? outer : pkg) + name).toLowerCase());
            clsNew.put(c.name, (outer != null ? outer : pkg) + name);
            statCls++;
        }
    }

    static final Set<String> JAVA_LANG = new HashSet<>(Arrays.asList("Object", "Class", "Enum", "String", "Integer", "Long", "Double", "Float", "Short", "Byte", "Character", "Boolean", "Number", "Thread", "Math", "System", "Runnable", "Exception", "Error", "Throwable", "Override", "Process", "Runtime", "Iterable", "Comparable", "Record", "Void", "StringBuilder", "Package", "Module", "Compiler", "Appendable", "ClassLoader", "ThreadLocal", "Readable", "Deprecated", "SafeVarargs", "Cloneable", "AutoCloseable", "CharSequence", "StackTraceElement", "SecurityManager", "Iterator", "List", "Map", "Set", "Collection", "Optional", "Random", "UUID", "Date", "Timer", "Logger", "Scanner", "Arrays", "Objects", "Collections", "Stream", "Function", "Consumer", "Supplier", "Predicate", "Path", "Files", "File", "Locale", "Properties", "Entry", "Callable"));

    String finalCls(String internal) { return clsNew.getOrDefault(internal, internal); }

    String typeWord(Type t) {
        switch (t.getSort()) {
            case Type.BOOLEAN: return "flag";
            case Type.INT: return "count";
            case Type.LONG: return "time";
            case Type.DOUBLE: return "amount";
            case Type.FLOAT: return "ratio";
            case Type.BYTE: case Type.SHORT: return "value";
            case Type.CHAR: return "ch";
            case Type.ARRAY: return typeWord(t.getElementType()) + "s";
            case Type.OBJECT: {
                String in = t.getInternalName();
                String s = simple(finalCls(in));
                switch (in) {
                    case "java/lang/String": return "text";
                    case "java/util/List": case "java/util/ArrayList": case "java/util/Collection": return "items";
                    case "java/util/Map": case "java/util/HashMap": case "java/util/concurrent/ConcurrentHashMap": return "entries";
                    case "java/util/Set": case "java/util/HashSet": return "values";
                    case "java/util/UUID": return "uuid";
                    case "java/lang/Object": return "object";
                    case "java/lang/Integer": return "number";
                    case "java/lang/Long": return "timestamp";
                    case "java/lang/Boolean": return "flag";
                    case "java/util/Random": return "random";
                    case "java/util/logging/Logger": return "logger";
                }
                return lcFirst(s);
            }
        }
        return "value";
    }

    void computeEnumConsts() {
        // enum sabitleri: new E("NAME", ordinal, ...) kurucu çağrılarından
        for (ClassNode c : classes.values()) {
            if ((c.access & ACC_ENUM) == 0) continue;
            MethodNode clinit = c.methods.stream().filter(m -> m.name.equals("<clinit>")).findFirst().orElse(null);
            if (clinit == null) continue;
            for (AbstractInsnNode i : clinit.instructions) {
                if (!(i instanceof FieldInsnNode f) || f.getOpcode() != PUTSTATIC || !f.owner.equals(c.name) || !f.desc.equals("L" + c.name + ";")) continue;
                // geriye bak: ldc "NAME" ardından iconst/bipush ordinal ... invokespecial <init> ... putstatic
                String nm = null;
                for (AbstractInsnNode p = f.getPrevious(); p != null; p = p.getPrevious()) {
                    if (p.getOpcode() == NEW) break;
                    if (p instanceof LdcInsnNode l && l.cst instanceof String s && s.matches("[A-Za-z_][A-Za-z0-9_]*")) nm = s;
                }
                if (nm != null && obfMember(f.name) && !fldNew.containsKey(c.name + "." + f.name)) { fldNew.put(c.name + "." + f.name, nm); statEnum++; }
            }
        }
    }

    void computeMemberNames() {
        // alan adları: tür + sayaç
        for (ClassNode c : classes.values()) {
            Map<String, Integer> cnt = new HashMap<>();
            Set<String> taken = new HashSet<>();
            for (FieldNode f : c.fields) if (!obfMember(f.name) || fldNew.containsKey(c.name + "." + f.name)) taken.add(fldNew.getOrDefault(c.name + "." + f.name, f.name));
            for (FieldNode f : c.fields) {
                String key = c.name + "." + f.name;
                if (!obfMember(f.name) || fldNew.containsKey(key)) continue;
                String base = typeWord(Type.getType(f.desc));
                if ((f.access & ACC_STATIC) != 0 && (f.access & ACC_FINAL) != 0 && Type.getType(f.desc).getSort() != Type.OBJECT) base = base.toUpperCase();
                String nm = base; int k = 1;
                while (taken.contains(nm) || isKeyword(nm)) { k++; nm = base + k; }
                taken.add(nm); fldNew.put(key, nm); statFld++;
            }
        }
        // metot adları (aynı imzalı üst sınıf / arayüz metotları aynı ad)
        Map<String, String> group = new HashMap<>();                 // owner.name+desc -> grup anahtarı
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) {
            if (!obfMember(m.name) || (m.access & (ACC_STATIC)) != 0 && false) continue;
            String key = c.name + "." + m.name + m.desc;
            String gkey = m.name + m.desc;
            // en üstteki tanımlayıcıyı bul
            for (String s : allSupers(c.name)) { ClassNode sc = classes.get(s); if (sc != null) for (MethodNode sm : sc.methods) if (sm.name.equals(m.name) && sm.desc.equals(m.desc)) gkey = s + "." + sm.name + sm.desc; }
            group.put(key, gkey);
        }
        Map<String, String> groupName = new HashMap<>();
        for (ClassNode c : classes.values()) {
            Set<String> taken = new HashSet<>();
            for (MethodNode m : c.methods) if (!obfMember(m.name)) taken.add(m.name + m.desc);
            for (MethodNode m : c.methods) {
                String key = c.name + "." + m.name + m.desc;
                if (!obfMember(m.name) || !group.containsKey(key)) continue;
                String g = group.get(key);
                String nm = groupName.get(g);
                if (nm == null) {
                    nm = methodNameFor(c, m);
                    String base = nm; int k = 1;
                    while (taken.contains(nm + m.desc) || isKeyword(nm)) { k++; nm = base + k; }
                    groupName.put(g, nm);
                    statMth++;
                }
                taken.add(nm + m.desc);
                mthNew.put(key, nm);
            }
        }
    }

    static final Set<String> KW = new HashSet<>(Arrays.asList("abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while"));
    static boolean isKeyword(String s) { return KW.contains(s); }

    String fieldNameFinal(String owner, String name) { String o = fieldNameOf(owner, name); return o; }
    String fieldNameOf(String owner, String name) { String r = fldNew.get(owner + "." + name); return r != null ? r : name; }

    String methodNameFor(ClassNode c, MethodNode m) {
        Type[] args = Type.getArgumentTypes(m.desc); Type ret = Type.getReturnType(m.desc);
        boolean isStatic = (m.access & ACC_STATIC) != 0;
        // getter: aload_0 getfield areturn
        List<AbstractInsnNode> real = new ArrayList<>();
        for (AbstractInsnNode i : m.instructions) if (i.getOpcode() >= 0) real.add(i);
        if (!isStatic && args.length == 0 && real.size() == 3 && real.get(0).getOpcode() == ALOAD && real.get(1) instanceof FieldInsnNode f && f.getOpcode() == GETFIELD && real.get(2).getOpcode() >= IRETURN && real.get(2).getOpcode() <= ARETURN) {
            String fn = fieldNameOf(f.owner, f.name);
            return (ret.getSort() == Type.BOOLEAN ? "is" : "get") + pascal(fn);
        }
        if (!isStatic && args.length == 1 && ret.getSort() == Type.VOID) {
            FieldInsnNode put = null; int cnt = 0;
            for (AbstractInsnNode i : real) if (i instanceof FieldInsnNode f2 && f2.getOpcode() == PUTFIELD) { put = f2; cnt++; }
            if (cnt == 1 && real.size() <= 5) return "set" + pascal(fieldNameOf(put.owner, put.name));
        }
        // gövdedeki baskın çağrı
        String verb = null;
        for (AbstractInsnNode i : real) if (i instanceof MethodInsnNode mi) {
            if (mi.owner.equals("java/util/List") || mi.owner.equals("java/util/Set") || mi.owner.equals("java/util/Collection")) { if (mi.name.equals("add")) { verb = "add"; break; } if (mi.name.equals("remove")) { verb = "remove"; break; } if (mi.name.equals("contains")) { verb = "has"; break; } }
            if (mi.owner.equals("java/util/Map")) { if (mi.name.equals("put")) { verb = "put"; break; } if (mi.name.equals("get")) { verb = "get"; break; } if (mi.name.equals("remove")) { verb = "remove"; break; } if (mi.name.equals("containsKey")) { verb = "has"; break; } }
        }
        String argWord = args.length > 0 ? pascal(typeWord(args[0])) : "";
        if (args.length > 0 && args[0].getSort() == Type.OBJECT && !args[0].getInternalName().startsWith("java/")) argWord = simple(finalCls(args[0].getInternalName()));
        if (verb != null) return verb + argWord;
        // new + dönüş türü
        if (ret.getSort() == Type.OBJECT && !ret.getInternalName().startsWith("java/")) {
            boolean creates = false;
            for (AbstractInsnNode i : real) if (i instanceof TypeInsnNode t && t.getOpcode() == NEW && t.desc.equals(ret.getInternalName())) creates = true;
            return (creates ? "create" : "get") + simple(finalCls(ret.getInternalName()));
        }
        if (ret.getSort() == Type.BOOLEAN) return "is" + (argWord.isEmpty() ? "Valid" : argWord);
        if (ret.getSort() == Type.VOID && args.length > 0) return "handle" + argWord;
        if (ret.getSort() == Type.VOID) return "run";
        if (ret.getSort() == Type.INT) return "compute" + argWord;
        return "method";
    }

    /* ============================================================ remapper */
    Remapper remapper() {
        return new Remapper() {
            @Override public String map(String internalName) {
                return clsNew.getOrDefault(internalName, internalName);
            }
            @Override public String mapFieldName(String owner, String name, String desc) {
                String o = fieldOwner(owner, name, desc);
                if (o == null) return name;
                String r = fldNew.get(o + "." + name);
                return r != null ? r : name;
            }
            @Override public String mapMethodName(String owner, String name, String desc) {
                String r = mthNew.get(owner + "." + name + desc);
                if (r != null) return r;
                // üst sınıflardan çöz
                for (String s : allSupers(owner)) { r = mthNew.get(s + "." + name + desc); if (r != null) return r; }
                return name;
            }
        };
    }

    void applyMapping() {
        // mapping.txt: sınıf adları
        for (var e : mapCls.entrySet()) if (classes.containsKey(e.getKey()) && !e.getKey().equals(e.getValue())) { clsNew.put(e.getKey(), e.getValue()); statMapped++; }
        for (var e : mapFld.entrySet()) { fldNew.put(e.getKey(), e.getValue()); }
        for (var e : mapMth.entrySet()) { mthNew.put(e.getKey(), e.getValue()); }
    }

    /* ============================================================ jar */
    void run(File in, File out, File mapping, Pattern filter) throws Exception {
        Map<String, byte[]> raw = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(in))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) if (!e.isDirectory()) raw.put(e.getName(), z.readAllBytes());
        }
        for (var e : raw.entrySet()) {
            if (!e.getKey().endsWith(".class")) continue;
            try {
                ClassNode cn = new ClassNode();
                new ClassReader(e.getValue()).accept(cn, ClassReader.SKIP_FRAMES);
                if (filter.matcher(cn.name.replace('/', '.')).find()) classes.put(cn.name, cn);
            } catch (Exception ex) { }
        }
        for (ClassNode cn : classes.values()) for (MethodNode m : cn.methods) splitLocals(cn, m);
        for (ClassNode cn : classes.values()) if ("java/lang/Enum".equals(cn.superName)) { cn.access |= ACC_ENUM; if (cn.signature == null) cn.signature = "Ljava/lang/Enum<L" + cn.name + ";>;"; }
        if (mapping != null) { loadMapping(mapping); applyMapping(); }
        else { computeEnumConsts(); computeClassNames(); computeMemberNames(); }

        Remapper rm = remapper();
        Map<String, byte[]> outClasses = new LinkedHashMap<>();
        for (ClassNode cn : classes.values()) {
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            cn.accept(new ClassRemapper(cw, rm));
            outClasses.put(cn.name, cw.toByteArray());
        }
        try (ZipOutputStream zo = new ZipOutputStream(new FileOutputStream(out))) {
            for (var e : raw.entrySet()) {
                String n = e.getKey();
                byte[] data = e.getValue(); String path = n;
                if (n.endsWith(".class")) {
                    String cname = n.substring(0, n.length() - 6);
                    if (outClasses.containsKey(cname)) { data = outClasses.get(cname); path = clsNew.getOrDefault(cname, cname) + ".class"; }
                }
                zo.putNextEntry(new ZipEntry(path));
                zo.write(data);
                zo.closeEntry();
            }
        }
        System.out.println("STATS {\"splitMethods\":" + statSplit + ",\"classes\":" + statCls + ",\"fields\":" + statFld + ",\"methods\":" + statMth
                + ",\"enumConsts\":" + statEnum + ",\"mapped\":" + statMapped + "}");
    }

    /** jar'daki sınıf adlarına bakarak ProGuard tarzı kısa ad kullanımını ölç */
    static void detect(File jar) throws Exception {
        int total = 0, obf = 0, memberObf = 0, members = 0;
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(jar))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                String n = e.getName();
                if (!n.endsWith(".class") || n.contains("/libs/") || n.startsWith("META-INF/")) continue;
                total++;
                if (obfClass(n.substring(0, n.length() - 6))) obf++;
                try {
                    ClassNode cn = new ClassNode();
                    new ClassReader(z.readAllBytes()).accept(cn, ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES);
                    for (MethodNode m : cn.methods) { if (m.name.startsWith("<")) continue; members++; if (obfMember(m.name)) memberObf++; }
                    for (FieldNode f : cn.fields) { members++; if (obfMember(f.name)) memberObf++; }
                } catch (Exception ex) { }
            }
        }
        System.out.println("STATS {\"total\":" + total + ",\"obfClasses\":" + obf + ",\"members\":" + members + ",\"obfMembers\":" + memberObf + "}");
    }

    public static void main(String[] a) throws Exception {
        if (a.length > 1 && a[0].equals("--detect")) { detect(new File(a[1])); return; }
        File mapping = null; Pattern f = Pattern.compile("^(?!.*\\blibs\\b)");
        for (int i = 2; i < a.length; i++) {
            if (a[i].equals("--mapping")) mapping = new File(a[++i]);
            else if (a[i].equals("--filter")) f = Pattern.compile(a[++i]);
        }
        new ProGuardClean().run(new File(a[0]), new File(a[1]), mapping, f);
    }
}
