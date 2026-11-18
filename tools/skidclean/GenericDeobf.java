import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * Genel bayt kodu deobf motoru (obfuscator'dan bağımsız teknikler):
 *   --detect jar            : obfuscator parmak izi (heuristik) -> STATS {"detected":[...]}
 *   jar out                 : 1) bozuk ZIP onarımı  2) sayı katlama  3) peephole / çöp komut  4) opaque predicate + ölü kod
 *                             5) referans proxy (tek satırlık yönlendirme metotları) açma  6) statik string şifre çözme (sandbox)
 *
 * Jar içindeki kod ASLA doğrudan çalıştırılmaz: string çözücüler, yalnızca beyaz listeli API kullanan
 * (String/StringBuilder/Math/Integer/...) kırpılmış bir stub sınıfta, ayrı class loader'da ve zaman aşımıyla çalıştırılır.
 */
public class GenericDeobf {
    final Map<String, ClassNode> classes = new LinkedHashMap<>();
    final Map<String, byte[]> resources = new LinkedHashMap<>();
    final Map<String, byte[]> original = new HashMap<>();
    int folded, peep, branches, dead, proxies, strings, badEntries;

    /* ============================================================ ZIP okuma (bozuk jar toleranslı) */
    void read(File jar) throws IOException {
        int ok = 0;
        try (ZipInputStream z = new ZipInputStream(new BufferedInputStream(new FileInputStream(jar)))) {
            ZipEntry e;
            while (true) {
                try { e = z.getNextEntry(); } catch (ZipException ex) { badEntries++; break; }
                if (e == null) break;
                if (e.isDirectory()) continue;
                byte[] data;
                try { data = z.readAllBytes(); } catch (IOException ex) { badEntries++; continue; }
                add(e.getName(), data); ok++;
            }
        } catch (IOException ex) { badEntries++; }
        if (ok == 0 || badEntries > 0) { // ZipFile (merkezi dizin) ile tekrar dene: bazı korumalar yerel başlıkları bozar
            try (ZipFile zf = new ZipFile(jar)) {
                for (Enumeration<? extends ZipEntry> en = zf.entries(); en.hasMoreElements(); ) {
                    ZipEntry e = en.nextElement();
                    if (e.isDirectory()) continue;
                    if (classes.containsKey(strip(e.getName())) || resources.containsKey(e.getName())) continue;
                    try (InputStream in = zf.getInputStream(e)) { add(e.getName(), in.readAllBytes()); } catch (IOException ex) { badEntries++; }
                }
            } catch (IOException ex) { /* merkezi dizin de bozuk */ }
        }
    }
    static String strip(String n) { return n.endsWith(".class") ? n.substring(0, n.length() - 6) : n; }
    void add(String name, byte[] data) {
        if (name.endsWith(".class") && data.length > 8 && (data[0] & 0xFF) == 0xCA && (data[1] & 0xFF) == 0xFE) {
            try {
                ClassNode cn = new ClassNode();
                new ClassReader(data).accept(cn, ClassReader.SKIP_FRAMES);
                classes.put(cn.name, cn); original.put(cn.name, data); return;
            } catch (Exception ex) { badEntries++; }
        }
        resources.put(name, data);
    }

    /* ============================================================ parmak izi */
    static final String[][] SIGS = {
        {"Allatori", "allatori"}, {"ZKM (Zelix KlassMaster)", "zelix", "zkm"}, {"Stringer", "com/licel", "stringer"},
        {"DashO", "com/preemptive", "dasho"}, {"Paramorphism", "paramorphism"}, {"Radon", "me/itzsomebody", "radon"},
        {"superblaubeere27", "superblaubeere27"}, {"Skidfuscator", "skidfuscator"}, {"Binscure", "binscure"}, {"JNIC", "dev/jnic", "jnic.dev"},
        {"Branchlock", "branchlock"}, {"qProtect", "qprotect"}, {"Caesium", "caesium"}, {"Bozar", "bozar"}, {"sim0n obfuscator", "sim0n"},
        {"Obfuscator by Cavallius/Cloud", "cloudobfuscator"}, {"JObf / JavaGuard", "javaguard", "jobf"}, {"yGuard", "yguard"},
        {"ProGuard", "proguard"}, {"DexGuard/R8", "dexguard"},
    };
    static List<String> fingerprint(File jar) throws IOException {
        Set<String> hit = new LinkedHashSet<>();
        GenericDeobf g = new GenericDeobf(); g.read(jar);
        List<byte[]> blobs = new ArrayList<>(g.resources.values());
        blobs.addAll(g.original.values());
        List<String> names = new ArrayList<>(g.resources.keySet()); names.addAll(g.classes.keySet());
        for (String n : names) scan(n.toLowerCase(Locale.ROOT), hit);
        for (byte[] b : blobs) { if (b.length > 4_000_000) continue; scan(new String(b, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT), hit); }
        // yapısal ipuçları
        int total = 0, shortCls = 0, weird = 0, decrypt = 0, indy = 0;
        for (ClassNode c : g.classes.values()) {
            total++; String s = c.name.substring(c.name.lastIndexOf('/') + 1);
            if (s.length() <= 2) shortCls++;
            if (!isIdent(s)) weird++;
            for (MethodNode m : c.methods) {
                if (!isIdent(m.name) && !m.name.startsWith("<")) weird++;
                if ((m.access & ACC_STATIC) != 0 && m.desc.endsWith(")Ljava/lang/String;") && m.instructions.size() > 20 && m.desc.startsWith("(Ljava/lang/String;")) decrypt++;
                for (AbstractInsnNode i : m.instructions) if (i instanceof InvokeDynamicInsnNode d && !d.bsm.getOwner().startsWith("java/lang/invoke/")) indy++;
            }
        }
        int confusing = 0, zkm = 0, stackKey = 0;
        for (ClassNode c : g.classes.values()) {
            String sn = c.name.substring(c.name.lastIndexOf('/') + 1); if (sn.matches("[IlLi1oO0]{4,}")) confusing++;
            boolean sa = false; for (FieldNode f : c.fields) if ((f.access & ACC_STATIC) != 0 && f.desc.equals("[Ljava/lang/String;")) sa = true;
            boolean ci = false, tc = false; for (MethodNode m : c.methods) if (m.name.equals("<clinit>")) { ci = true; for (AbstractInsnNode i : m.instructions) if (i instanceof MethodInsnNode mi && mi.name.equals("toCharArray")) tc = true; }
            if (sa && ci && tc) zkm++;
            for (MethodNode m : c.methods) if (candidate(m) && stackDep(m)) stackKey++;
        }
        if (confusing >= 3) hit.add("Karışık I/l/1/O adları (Allatori/ProGuard tarzı) (" + confusing + ")");
        if (zkm >= 2) hit.add("ZKM tarzı <clinit> şifreli static String[] (" + zkm + " sınıf)");
        if (stackKey >= 1) hit.add("Yığın izi anahtarlı string çözücü (Allatori V3/V4 strong tarzı) (" + stackKey + ")");
        if (weird > 0) hit.add("Geçersiz/yazdırılamaz adlar (" + weird + ")");
        if (total > 5 && shortCls * 2 > total) hit.add("Kısa ad gizleme (a, b, c…)");
        if (decrypt >= 3) hit.add("Statik string şifre çözücüler (" + decrypt + ")");
        if (indy >= 5) hit.add("Özel invokedynamic referans gizleme (" + indy + ")");
        if (g.badEntries > 0) hit.add("Bozuk ZIP girdileri (" + g.badEntries + ") — anti-unzip koruması");
        return new ArrayList<>(hit);
    }
    static void scan(String hay, Set<String> hit) {
        for (String[] s : SIGS) for (int i = 1; i < s.length; i++) if (hay.contains(s[i])) { hit.add(s[0]); break; }
    }
    static boolean isIdent(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (!(Character.isJavaIdentifierPart(c) && c < 0x80) ) return false; }
        return Character.isJavaIdentifierStart(s.charAt(0));
    }

    /* ============================================================ sabit yardımcıları */
    static boolean real(AbstractInsnNode i) { return i.getOpcode() != -1; }
    static AbstractInsnNode prevReal(AbstractInsnNode i) { AbstractInsnNode p = i.getPrevious(); while (p != null && !real(p)) p = p.getPrevious(); return p; }
    static AbstractInsnNode nextReal(AbstractInsnNode i) { AbstractInsnNode p = i.getNext(); while (p != null && !real(p)) p = p.getNext(); return p; }
    static Object cst(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op >= ICONST_M1 && op <= ICONST_5) return op - ICONST_0;
        if (op == BIPUSH || op == SIPUSH) return ((IntInsnNode) in).operand;
        if (op == LCONST_0) return 0L; if (op == LCONST_1) return 1L;
        if (op == LDC) { Object c = ((LdcInsnNode) in).cst; if (c instanceof Integer || c instanceof Long) return c; }
        return null;
    }
    static AbstractInsnNode push(Object v) {
        if (v instanceof Long l) return l == 0 ? new InsnNode(LCONST_0) : l == 1 ? new InsnNode(LCONST_1) : new LdcInsnNode(l);
        int i = (Integer) v;
        if (i >= -1 && i <= 5) return new InsnNode(ICONST_0 + i);
        if (i >= Byte.MIN_VALUE && i <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, i);
        if (i >= Short.MIN_VALUE && i <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, i);
        return new LdcInsnNode(i);
    }
    static Object bin(int op, Object a, Object b) {
        if (a instanceof Integer x && b instanceof Integer y) switch (op) {
            case IADD: return x + y; case ISUB: return x - y; case IMUL: return x * y;
            case IDIV: return y == 0 ? null : (Object) (x / y); case IREM: return y == 0 ? null : (Object) (x % y);
            case ISHL: return x << y; case ISHR: return x >> y; case IUSHR: return x >>> y;
            case IAND: return x & y; case IOR: return x | y; case IXOR: return x ^ y;
        }
        if (a instanceof Long x && b instanceof Long y) switch (op) {
            case LADD: return x + y; case LSUB: return x - y; case LMUL: return x * y;
            case LDIV: return y == 0 ? null : (Object) (x / y); case LREM: return y == 0 ? null : (Object) (x % y);
            case LAND: return x & y; case LOR: return x | y; case LXOR: return x ^ y;
            case LCMP: return Long.compare(x, y);
        }
        if (a instanceof Long x && b instanceof Integer y) switch (op) {
            case LSHL: return x << y; case LSHR: return x >> y; case LUSHR: return x >>> y;
        }
        return null;
    }
    static Object un(int op, Object a) {
        if (a instanceof Integer x) switch (op) {
            case INEG: return -x; case I2L: return (long) x; case I2B: return (int) (byte) (int) x;
            case I2C: return (int) (char) (int) x; case I2S: return (int) (short) (int) x;
        }
        if (a instanceof Long x) switch (op) { case LNEG: return -x; case L2I: return (int) (long) x; }
        return null;
    }
    static boolean isBin(int op) { return switch (op) { case IADD, LADD, ISUB, LSUB, IMUL, LMUL, IDIV, LDIV, IREM, LREM, ISHL, LSHL, ISHR, LSHR, IUSHR, LUSHR, IAND, LAND, IOR, LOR, IXOR, LXOR, LCMP -> true; default -> false; }; }

    /* ============================================================ metot dönüşümleri */
    void method(ClassNode cn, MethodNode m) {
        if (m.instructions.size() == 0) return;
        sanitizeDebugInfo(m);
        cleanTryCatch(m);
        for (int round = 0; round < 12; round++) {
            boolean ch = false;
            ch |= foldNumbers(m);
            ch |= foldIdentities(m);
            ch |= peephole(m);
            ch |= branchFold(m);
            ch |= threadJumps(m);
            ch |= removeDead(cn, m);
            if (!ch) break;
        }
    }

    void sanitizeDebugInfo(MethodNode m) {
        Set<Integer> seen = new HashSet<>();
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
            AbstractInsnNode next = in.getNext();
            if (in instanceof LineNumberNode ln) {
                if (ln.line <= 0 || ln.line >= 65000 || !seen.add(ln.line)) {
                    m.instructions.remove(in);
                    peep++;
                }
            }
            in = next;
        }
        if (m.localVariables != null) {
            m.localVariables.removeIf(lv -> lv.name == null || lv.name.isEmpty() || lv.name.contains("\u0000") || lv.name.length() > 200);
        }
    }

    boolean cleanTryCatch(MethodNode m) {
        if (m.tryCatchBlocks == null || m.tryCatchBlocks.isEmpty()) return false;
        boolean ch = m.tryCatchBlocks.removeIf(t -> {
            if (t.start == t.end) return true;
            AbstractInsnNode p = t.start.getNext();
            while (p != null && p != t.end && !real(p)) p = p.getNext();
            if (p == null || p == t.end) return true;
            AbstractInsnNode h = nextReal(t.handler);
            if (h != null && h.getOpcode() == ATHROW) return true;
            if (h instanceof VarInsnNode v && (v.getOpcode() == ASTORE)) {
                AbstractInsnNode h2 = nextReal(h);
                if (h2 instanceof VarInsnNode v2 && v2.getOpcode() == ALOAD && v.var == v2.var) {
                    AbstractInsnNode h3 = nextReal(h2);
                    if (h3 != null && h3.getOpcode() == ATHROW) return true;
                }
            }
            if (h != null && (h.getOpcode() == POP || h.getOpcode() == ASTORE)) {
                AbstractInsnNode h2 = nextReal(h);
                if (h2 != null && h2.getOpcode() == GOTO) {
                    boolean canThrow = false;
                    for (AbstractInsnNode cur = t.start; cur != null && cur != t.end; cur = cur.getNext()) {
                        int cop = cur.getOpcode();
                        if (cop >= INVOKEVIRTUAL && cop <= INVOKEINTERFACE) { canThrow = true; break; }
                        if (cop == ATHROW || cop == CHECKCAST || cop == ANEWARRAY || cop == NEWARRAY || cop == MULTIANEWARRAY || cop == MONITORENTER || cop == MONITOREXIT) { canThrow = true; break; }
                        if (cop == IDIV || cop == IREM || cop == LDIV || cop == LREM) { canThrow = true; break; }
                    }
                    if (!canThrow) return true;
                }
            }
            return false;
        });
        if (ch) peep++;
        return ch;
    }

    static boolean isLoadStorePair(AbstractInsnNode load, AbstractInsnNode store) {
        if (load == null || store == null) return false;
        int lo = load.getOpcode(), so = store.getOpcode();
        boolean match = (lo == ILOAD && so == ISTORE) || (lo == LLOAD && so == LSTORE) || (lo == FLOAD && so == FSTORE)
                || (lo == DLOAD && so == DSTORE) || (lo == ALOAD && so == ASTORE);
        return match && ((VarInsnNode) load).var == ((VarInsnNode) store).var;
    }

    static boolean isSameVar(AbstractInsnNode a, AbstractInsnNode b) {
        if (a == null || b == null || a.getOpcode() != b.getOpcode()) return false;
        int op = a.getOpcode();
        if ((op >= ILOAD && op <= ALOAD) || (op >= ISTORE && op <= ASTORE)) {
            return ((VarInsnNode) a).var == ((VarInsnNode) b).var;
        }
        return false;
    }

    boolean foldIdentities(MethodNode m) {
        boolean ch = false;
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
            AbstractInsnNode next = in.getNext();
            int op = in.getOpcode();

            if (op == INEG || op == LNEG || op == FNEG || op == DNEG) {
                AbstractInsnNode p = prevReal(in);
                if (p != null && p.getOpcode() == op && noLabelBetween(p, in)) {
                    m.instructions.remove(p);
                    m.instructions.remove(in);
                    folded++; ch = true;
                    in = next; continue;
                }
            }

            if (op == IXOR || op == LXOR) {
                AbstractInsnNode b = prevReal(in);
                Object cb = cst(b);
                boolean isNot = (op == IXOR && cb instanceof Integer iv && iv == -1) || (op == LXOR && cb instanceof Long lv && lv == -1L);
                if (isNot) {
                    AbstractInsnNode a = prevReal(b);
                    if (a != null && a.getOpcode() == op) {
                        AbstractInsnNode prevCst = prevReal(a);
                        Object ca = cst(prevCst);
                        boolean prevIsNot = (op == IXOR && ca instanceof Integer iv2 && iv2 == -1) || (op == LXOR && ca instanceof Long lv2 && lv2 == -1L);
                        if (prevIsNot && noLabelBetween(prevCst, in)) {
                            m.instructions.remove(prevCst);
                            m.instructions.remove(a);
                            m.instructions.remove(b);
                            m.instructions.remove(in);
                            folded += 2; ch = true;
                            in = next; continue;
                        }
                    }
                }
            }

            if (isBin(op)) {
                AbstractInsnNode b = prevReal(in);
                AbstractInsnNode a = b == null ? null : prevReal(b);
                if (a != null && b != null && noLabelBetween(a, in)) {
                    if (isSameVar(a, b)) {
                        if (op == IXOR || op == ISUB) {
                            m.instructions.insertBefore(a, new InsnNode(ICONST_0));
                            m.instructions.remove(a); m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                        if (op == LXOR || op == LSUB) {
                            m.instructions.insertBefore(a, new InsnNode(LCONST_0));
                            m.instructions.remove(a); m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                        if (op == FSUB) {
                            m.instructions.insertBefore(a, new InsnNode(FCONST_0));
                            m.instructions.remove(a); m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                        if (op == DSUB) {
                            m.instructions.insertBefore(a, new InsnNode(DCONST_0));
                            m.instructions.remove(a); m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                    }

                    Object cb = cst(b), ca = cst(a);
                    if (cb instanceof Integer vb) {
                        if (vb == 0) {
                            if (op == IXOR || op == IOR || op == IADD || op == ISUB || op == ISHL || op == ISHR || op == IUSHR || op == LSHL || op == LSHR || op == LUSHR) {
                                m.instructions.remove(b); m.instructions.remove(in);
                                folded++; ch = true; in = next; continue;
                            }
                            if ((op == IMUL || op == IAND) && (a instanceof VarInsnNode)) {
                                m.instructions.remove(a); m.instructions.set(in, new InsnNode(ICONST_0)); m.instructions.remove(b);
                                folded++; ch = true; in = next; continue;
                            }
                        } else if (vb == 1) {
                            if (op == IMUL || op == IDIV) {
                                m.instructions.remove(b); m.instructions.remove(in);
                                folded++; ch = true; in = next; continue;
                            }
                        } else if (vb == -1) {
                            if (op == IAND) {
                                m.instructions.remove(b); m.instructions.remove(in);
                                folded++; ch = true; in = next; continue;
                            }
                        }
                    }
                    if (ca instanceof Integer va) {
                        if (va == 0) {
                            if (op == IXOR || op == IOR || op == IADD) {
                                m.instructions.remove(a); m.instructions.remove(in);
                                folded++; ch = true; in = next; continue;
                            }
                            if ((op == IMUL || op == IAND) && (b instanceof VarInsnNode)) {
                                m.instructions.remove(b); m.instructions.set(in, new InsnNode(ICONST_0)); m.instructions.remove(a);
                                folded++; ch = true; in = next; continue;
                            }
                        } else if (va == 1 && op == IMUL) {
                            m.instructions.remove(a); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        } else if (va == -1 && op == IAND) {
                            m.instructions.remove(a); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                    }
                    if (cb instanceof Long vb) {
                        if (vb == 0L && (op == LXOR || op == LOR || op == LADD || op == LSUB)) {
                            m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                        if (vb == 1L && (op == LMUL || op == LDIV)) {
                            m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                        if (vb == -1L && op == LAND) {
                            m.instructions.remove(b); m.instructions.remove(in);
                            folded++; ch = true; in = next; continue;
                        }
                    }
                }
            }
            in = next;
        }
        return ch;
    }

    boolean foldNumbers(MethodNode m) {
        boolean ch = false;
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
            AbstractInsnNode next = in.getNext();
            int op = in.getOpcode();
            if (isBin(op)) {
                {
                    AbstractInsnNode b = prevReal(in), a = b == null ? null : prevReal(b);
                    Object cb = cst(b), ca = cst(a);
                    if (ca != null && cb != null && noLabelBetween(a, in)) {
                        Object r = bin(op, ca, cb);
                        if (r != null) { m.instructions.insertBefore(a, push(r)); m.instructions.remove(a); m.instructions.remove(b); m.instructions.remove(in); folded++; ch = true; }
                    }
                }
            } else if (op == INEG || op == LNEG || op == I2L || op == L2I || op == I2B || op == I2C || op == I2S) {
                AbstractInsnNode a = prevReal(in); Object ca = cst(a);
                if (ca != null && noLabelBetween(a, in)) {
                    Object r = un(op, ca);
                    if (r != null) { m.instructions.insertBefore(a, push(r)); m.instructions.remove(a); m.instructions.remove(in); folded++; ch = true; }
                }
            }
            in = next;
        }
        return ch;
    }
    /** a ile b arasında etiket (atlama hedefi) varsa katlama güvensiz */
    static boolean noLabelBetween(AbstractInsnNode a, AbstractInsnNode b) {
        for (AbstractInsnNode p = a.getNext(); p != null && p != b; p = p.getNext()) if (p instanceof LabelNode) return false;
        return true;
    }

    boolean peephole(MethodNode m) {
        boolean ch = false;
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
            AbstractInsnNode next = in.getNext();
            int op = in.getOpcode();
            if (op == NOP) { m.instructions.remove(in); peep++; ch = true; }
            else if (isLoadStorePair(prevReal(in), in) && noLabelBetween(prevReal(in), in)) {
                AbstractInsnNode p = prevReal(in);
                m.instructions.remove(p);
                m.instructions.remove(in);
                peep++; ch = true; in = next; continue;
            }
            else if (op == IINC && ((IincInsnNode) in).incr == 0) {
                m.instructions.remove(in);
                peep++; ch = true; in = next; continue;
            }
            else if (op == L2I) {
                AbstractInsnNode p = prevReal(in);
                if (p != null && p.getOpcode() == I2L && noLabelBetween(p, in)) {
                    m.instructions.remove(p);
                    m.instructions.remove(in);
                    peep++; ch = true; in = next; continue;
                }
            }
            else if (op == POP || op == POP2) {
                AbstractInsnNode p = prevReal(in);
                if (p != null && noLabelBetween(p, in)) {
                    int po = p.getOpcode();
                    boolean one = op == POP && (po == DUP || po == ACONST_NULL || (po >= ICONST_M1 && po <= ICONST_5) || po == BIPUSH || po == SIPUSH || po == FCONST_0 || po == FCONST_1
                            || (po == LDC && !(((LdcInsnNode) p).cst instanceof Long || ((LdcInsnNode) p).cst instanceof Double)) || (po >= ILOAD && po <= ALOAD));
                    boolean two = op == POP2 && (po == LCONST_0 || po == LCONST_1 || po == DCONST_0 || po == DCONST_1 || (po == LDC && (((LdcInsnNode) p).cst instanceof Long || ((LdcInsnNode) p).cst instanceof Double))
                            || po == DUP2 || po == LLOAD || po == DLOAD);
                    if (one || two) { m.instructions.remove(p); m.instructions.remove(in); peep++; ch = true; }
                }
            } else if (op == DUP) {
                AbstractInsnNode n = nextReal(in);
                if (n != null && n.getOpcode() == POP && noLabelBetween(in, n)) {
                    m.instructions.remove(n); m.instructions.remove(in); peep++; ch = true;
                }
            } else if (op == DUP2) {
                AbstractInsnNode n = nextReal(in);
                if (n != null && n.getOpcode() == POP2 && noLabelBetween(in, n)) {
                    m.instructions.remove(n); m.instructions.remove(in); peep++; ch = true;
                }
            } else if (op == CHECKCAST) {
                TypeInsnNode ti = (TypeInsnNode) in;
                if (ti.desc.equals("java/lang/Object")) {
                    m.instructions.remove(in); peep++; ch = true;
                }
            } else if (op == SWAP) {
                AbstractInsnNode n = nextReal(in);
                if (n != null && n.getOpcode() == SWAP && noLabelBetween(in, n)) { m.instructions.remove(n); m.instructions.remove(in); peep++; ch = true; }
                else if (n != null && noLabelBetween(in, n)) {
                    int no = n.getOpcode();
                    if (no == IADD || no == IMUL || no == IAND || no == IOR || no == IXOR || no == LADD || no == LMUL || no == LAND || no == LOR || no == LXOR) {
                        m.instructions.remove(in); peep++; ch = true;
                    }
                }
            } else if (op == GOTO) {
                AbstractInsnNode n = nextReal(in);
                if (n == null) { in = next; continue; }
                LabelNode t = ((JumpInsnNode) in).label;
                for (AbstractInsnNode p = in.getNext(); p != null; p = p.getNext()) { if (p == t) { m.instructions.remove(in); peep++; ch = true; break; } if (real(p)) break; }
            }
            in = next;
        }
        return ch;
    }

    boolean branchFold(MethodNode m) {
        boolean ch = false;
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
            AbstractInsnNode next = in.getNext();
            if (in instanceof JumpInsnNode j) {
                int op = j.getOpcode();
                Boolean take = null; AbstractInsnNode r1 = null, r2 = null;
                if (op >= IFEQ && op <= IFLE) {
                    r1 = prevReal(in); Object c = cst(r1);
                    if (c instanceof Integer v && noLabelBetween(r1, in)) take = switch (op) { case IFEQ -> v == 0; case IFNE -> v != 0; case IFLT -> v < 0; case IFGE -> v >= 0; case IFGT -> v > 0; default -> v <= 0; };
                } else if (op >= IF_ICMPEQ && op <= IF_ICMPLE) {
                    r2 = prevReal(in); r1 = r2 == null ? null : prevReal(r2);
                    Object b = cst(r2), a = cst(r1);
                    if (a instanceof Integer x && b instanceof Integer y && noLabelBetween(r1, in)) {
                        take = switch (op) { case IF_ICMPEQ -> x.equals(y); case IF_ICMPNE -> !x.equals(y); case IF_ICMPLT -> x < y; case IF_ICMPGE -> x >= y; case IF_ICMPGT -> x > y; default -> x <= y; };
                    } else if (r1 != null && r2 != null && isSameVar(r1, r2) && noLabelBetween(r1, in)) {
                        take = switch (op) { case IF_ICMPEQ, IF_ICMPGE, IF_ICMPLE -> true; default -> false; };
                    }
                } else if (op == IF_ACMPEQ || op == IF_ACMPNE) {
                    r2 = prevReal(in); r1 = r2 == null ? null : prevReal(r2);
                    if (r1 != null && r2 != null && noLabelBetween(r1, in)) {
                        if (isSameVar(r1, r2) || (r1.getOpcode() == ACONST_NULL && r2.getOpcode() == ACONST_NULL)) {
                            take = op == IF_ACMPEQ;
                        }
                    }
                } else if (op == IFNULL || op == IFNONNULL) {
                    r1 = prevReal(in);
                    if (r1 != null && r1.getOpcode() == ACONST_NULL && noLabelBetween(r1, in)) take = op == IFNULL;
                }
                if (take != null) {
                    if (r1 != null) m.instructions.remove(r1); if (r2 != null) m.instructions.remove(r2);
                    if (take) m.instructions.set(in, new JumpInsnNode(GOTO, j.label)); else m.instructions.remove(in);
                    branches++; ch = true;
                }
            } else if (in instanceof TableSwitchInsnNode t) {
                Set<LabelNode> targets = new HashSet<>(t.labels);
                targets.add(t.dflt);
                if (targets.size() == 1) {
                    LabelNode target = t.dflt;
                    m.instructions.insertBefore(in, new InsnNode(POP));
                    m.instructions.set(in, new JumpInsnNode(GOTO, target));
                    branches++; ch = true;
                } else {
                    AbstractInsnNode p = prevReal(in); Object c = cst(p);
                    if (c instanceof Integer v && noLabelBetween(p, in)) {
                        LabelNode target = (v >= t.min && v <= t.max) ? t.labels.get(v - t.min) : t.dflt;
                        m.instructions.remove(p); m.instructions.set(in, new JumpInsnNode(GOTO, target)); branches++; ch = true;
                    }
                }
            } else if (in instanceof LookupSwitchInsnNode l) {
                Set<LabelNode> targets = new HashSet<>(l.labels);
                targets.add(l.dflt);
                if (targets.size() == 1) {
                    LabelNode target = l.dflt;
                    m.instructions.insertBefore(in, new InsnNode(POP));
                    m.instructions.set(in, new JumpInsnNode(GOTO, target));
                    branches++; ch = true;
                } else {
                    AbstractInsnNode p = prevReal(in); Object c = cst(p);
                    if (c instanceof Integer v && noLabelBetween(p, in)) {
                        int ix = l.keys.indexOf(v); LabelNode target = ix >= 0 ? l.labels.get(ix) : l.dflt;
                        m.instructions.remove(p); m.instructions.set(in, new JumpInsnNode(GOTO, target)); branches++; ch = true;
                    }
                }
            }
            in = next;
        }
        return ch;
    }

    /** goto -> goto zincirlerini kısalt */
    boolean threadJumps(MethodNode m) {
        boolean ch = false;
        for (AbstractInsnNode in : m.instructions) {
            if (!(in instanceof JumpInsnNode j)) continue;
            LabelNode t = j.label;
            for (int hop = 0; hop < 8; hop++) {
                AbstractInsnNode n = nextReal(t);
                if (n instanceof JumpInsnNode g && g.getOpcode() == GOTO && g.label != t) { t = g.label; } else break;
            }
            if (t != j.label) { j.label = t; ch = true; peep++; }
        }
        return ch;
    }

    boolean removeDead(ClassNode cn, MethodNode m) {
        Frame<BasicValue>[] f;
        try { f = new Analyzer<>(new BasicInterpreter()).analyze(cn.name, m); } catch (Exception | StackOverflowError e) { return false; }
        boolean ch = false; int idx = 0;
        List<AbstractInsnNode> kill = new ArrayList<>();
        for (AbstractInsnNode in : m.instructions) {
            if (f[idx] == null && !(in instanceof LabelNode) && !(in instanceof LineNumberNode) && !(in instanceof FrameNode)) kill.add(in);
            idx++;
        }
        for (AbstractInsnNode k : kill) { m.instructions.remove(k); dead++; ch = true; }
        if (ch) {
            m.tryCatchBlocks.removeIf(t -> {
                AbstractInsnNode p = t.start; while (p != null && p != t.end && !real(p)) p = p.getNext();
                return p == t.end;
            });
            // Düşme noktası kalmayan metot sonu: ASM bunu zaten reddeder; analiz tekrar doğrular
            try { new Analyzer<>(new BasicInterpreter()).analyze(cn.name, m); } catch (Exception e) { /* üst katman geri alır */ }
        }
        return ch;
    }

    /* ============================================================ referans proxy açma */
    static final class Proxy { final AbstractInsnNode target; int uses; Proxy(AbstractInsnNode t) { target = t; } }
    final Map<String, Proxy> proxyMap = new HashMap<>();

    void findProxies() {
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) {
            if ((m.access & ACC_STATIC) == 0 || m.name.startsWith("<") || (m.access & ACC_ABSTRACT) != 0) continue;
            List<AbstractInsnNode> body = new ArrayList<>();
            for (AbstractInsnNode i : m.instructions) if (real(i)) body.add(i);
            Type[] args = Type.getArgumentTypes(m.desc);
            if (body.size() != args.length + 2 || body.size() > 12) continue;
            int slot = 0; boolean ok = true;
            for (int k = 0; k < args.length && ok; k++) {
                AbstractInsnNode i = body.get(k);
                ok = i instanceof VarInsnNode v && v.getOpcode() == args[k].getOpcode(ILOAD) && v.var == slot; slot += args[k].getSize();
            }
            if (!ok) continue;
            AbstractInsnNode call = body.get(args.length), ret = body.get(args.length + 1);
            Type rt = Type.getReturnType(m.desc);
            if (ret.getOpcode() != rt.getOpcode(IRETURN)) continue;
            if (call instanceof MethodInsnNode mi && mi.getOpcode() != INVOKESPECIAL) {
                Type[] ta = Type.getArgumentTypes(mi.desc);
                boolean st = mi.getOpcode() == INVOKESTATIC;
                if (st ? !mi.desc.equals(m.desc) : (ta.length + 1 != args.length || !Type.getReturnType(mi.desc).equals(rt))) continue;
                if (mi.owner.equals(c.name) && mi.name.equals(m.name) && mi.desc.equals(m.desc)) continue;
                proxyMap.put(c.name + "." + m.name + m.desc, new Proxy(mi));
            } else if (call instanceof FieldInsnNode fi && (fi.getOpcode() == GETSTATIC || fi.getOpcode() == GETFIELD) && args.length == (fi.getOpcode() == GETFIELD ? 1 : 0)
                    && Type.getType(fi.desc).equals(rt)) {
                proxyMap.put(c.name + "." + m.name + m.desc, new Proxy(fi));
            }
        }
    }
    void inlineProxies() {
        if (proxyMap.isEmpty()) return;
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) {
            for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
                AbstractInsnNode next = in.getNext();
                if (in instanceof MethodInsnNode mi && mi.getOpcode() == INVOKESTATIC) {
                    Proxy p = proxyMap.get(mi.owner + "." + mi.name + mi.desc);
                    if (p != null) { m.instructions.set(in, p.target.clone(new HashMap<>())); p.uses++; proxies++; }
                }
                in = next;
            }
        }
        // kullanılmayan (tamamen açılmış) proxy metotlarını sil
        Set<String> still = new HashSet<>();
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) for (AbstractInsnNode i : m.instructions) if (i instanceof MethodInsnNode mi) still.add(mi.owner + "." + mi.name + mi.desc);
        for (ClassNode c : classes.values()) c.methods.removeIf(m -> { String k = c.name + "." + m.name + m.desc; Proxy p = proxyMap.get(k); return p != null && p.uses > 0 && !still.contains(k); });
    }

    /* ============================================================ statik string çözme (sandbox) */
    static final Set<String> WL = new HashSet<>(Arrays.asList("java/lang/String", "java/lang/StringBuilder", "java/lang/StringBuffer", "java/lang/Object", "java/lang/Integer", "java/lang/Character",
            "java/lang/Long", "java/lang/Short", "java/lang/Byte", "java/lang/Boolean", "java/lang/Math", "java/util/Arrays", "java/lang/CharSequence", "java/lang/System",
            "java/lang/Throwable", "java/lang/StackTraceElement", "java/nio/charset/StandardCharsets", "java/nio/charset/Charset", "java/util/Base64", "java/util/Base64$Decoder", "java/lang/Class"));
    static final Set<String> BAD_SYS = new HashSet<>(Arrays.asList("exit", "load", "loadLibrary", "setProperty", "setSecurityManager", "getenv", "getProperty", "runFinalization", "setIn", "setOut", "setErr", "console", "getProperties", "clearProperty", "lineSeparator.x"));

    static boolean safeInsn(AbstractInsnNode i, String self) {
        if (i instanceof InvokeDynamicInsnNode d) return d.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory");
        if (i instanceof MethodInsnNode mi) {
            if (mi.owner.equals(self)) return true;
            if (mi.owner.startsWith("[")) return true;
            if (mi.owner.equals("java/lang/System")) return mi.name.equals("arraycopy") || mi.name.equals("identityHashCode");
            if (mi.owner.equals("java/lang/Class")) return false;
            if (mi.owner.equals("java/lang/Thread")) return mi.name.equals("currentThread") || mi.name.equals("getStackTrace");
            return WL.contains(mi.owner);
        }
        if (i instanceof FieldInsnNode fi) return fi.owner.equals(self) || WL.contains(fi.owner);
        if (i instanceof TypeInsnNode t) return t.desc.startsWith("[") || t.desc.equals(self) || WL.contains(t.desc);
        if (i instanceof MultiANewArrayInsnNode) return true;
        if (i instanceof LdcInsnNode l && l.cst instanceof Handle) return false;
        return true;
    }
    static boolean safeMethod(MethodNode m, String self) {
        for (AbstractInsnNode i : m.instructions) if (!safeInsn(i, self)) return false;
        return true;
    }

    static class Loader extends ClassLoader {
        final Map<String, byte[]> defs = new HashMap<>();
        Loader() { super(ClassLoader.getPlatformClassLoader()); }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            byte[] b = defs.get(n); if (b == null) throw new ClassNotFoundException(n);
            return defineClass(n, b, 0, b.length);
        }
    }

    static boolean candidate(MethodNode m) {
        if ((m.access & ACC_STATIC) == 0) return false;
        if (!Type.getReturnType(m.desc).getDescriptor().equals("Ljava/lang/String;")) return false;
        Type[] a = Type.getArgumentTypes(m.desc);
        if (a.length == 0 || a.length > 4) return false;
        for (Type t : a) { int s = t.getSort(); if (!(s == Type.INT || s == Type.SHORT || s == Type.BYTE || s == Type.CHAR || s == Type.LONG || (t.getDescriptor().equals("Ljava/lang/String;")))) return false; }
        return m.instructions.size() >= 8;
    }

    static boolean stackDep(MethodNode m) {
        for (AbstractInsnNode i : m.instructions) if (i instanceof MethodInsnNode mi && mi.name.equals("getStackTrace")) return true;
        return false;
    }
    final Map<String, Method> sandboxed = new HashMap<>();
    final Set<String> badSandbox = new HashSet<>();
    final ExecutorService pool = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "gd-sandbox"); t.setDaemon(true); return t; });

    ClassNode stub(ClassNode owner, MethodNode dec, boolean keepClinit) {
        ClassNode st = new ClassNode();
        st.version = V1_8; st.access = ACC_PUBLIC; st.name = owner.name; st.superName = "java/lang/Object";
        for (FieldNode f : owner.fields) if ((f.access & ACC_STATIC) != 0) st.fields.add(new FieldNode((f.access & ~(ACC_PRIVATE | ACC_PROTECTED)) | ACC_PUBLIC, f.name, f.desc, null, f.value));
        for (MethodNode m : owner.methods) {
            boolean keep = (m.access & ACC_STATIC) != 0 && (m.access & ACC_NATIVE) == 0 && (m.access & ACC_ABSTRACT) == 0;
            if (!keep) continue;
            if (!safeMethod(m, owner.name)) {
                if ((m.name.equals("<clinit>") && keepClinit) || (dec != null && m.name.equals(dec.name) && m.desc.equals(dec.desc))) return null;
                continue;
            }
            MethodNode c = new MethodNode(m.access, m.name, m.desc, null, null);
            c.access = (m.access & ~(ACC_PRIVATE | ACC_PROTECTED)) | ACC_PUBLIC;
            m.accept(c); st.methods.add(c);
        }
        return st;
    }
    static byte[] bytes(ClassNode n) {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) { @Override protected String getCommonSuperClass(String a, String b) { return "java/lang/Object"; } };
        n.accept(w); return w.toByteArray();
    }

    Method sandbox(ClassNode owner, MethodNode dec) {
        String key = owner.name + "." + dec.name + dec.desc;
        if (sandboxed.containsKey(key)) return sandboxed.get(key);
        if (badSandbox.contains(owner.name)) return null;
        try {
            ClassNode st = stub(owner, dec, true);
            if (st == null) { badSandbox.add(owner.name); return null; }
            Loader l = new Loader(); l.defs.put(owner.name.replace('/', '.'), bytes(st));
            Class<?> k = Class.forName(owner.name.replace('/', '.'), false, l);
            Method meth = null;
            for (Method x : k.getDeclaredMethods()) if (x.getName().equals(dec.name) && Type.getMethodDescriptor(x).equals(dec.desc)) meth = x;
            if (meth == null) { sandboxed.put(key, null); return null; }
            Class<?> kk = k;
            pool.submit(() -> { Class.forName(kk.getName(), true, kk.getClassLoader()); return null; }).get(4, TimeUnit.SECONDS);
            sandboxed.put(key, meth); return meth;
        } catch (Throwable t) { sandboxed.put(key, null); badSandbox.add(owner.name); return null; }
    }

    /* ---- yığın izi anahtarlı çözücüler (Allatori V3/V4 strong vb.): çağıran sınıf+metot adı sahte bir trampolinle taklit edilir ---- */
    static void unbox(MethodVisitor mv, Type t) {
        switch (t.getSort()) {
            case Type.INT -> { mv.visitTypeInsn(CHECKCAST, "java/lang/Integer"); mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false); }
            case Type.CHAR -> { mv.visitTypeInsn(CHECKCAST, "java/lang/Character"); mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false); }
            case Type.BYTE -> { mv.visitTypeInsn(CHECKCAST, "java/lang/Byte"); mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false); }
            case Type.SHORT -> { mv.visitTypeInsn(CHECKCAST, "java/lang/Short"); mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false); }
            case Type.LONG -> { mv.visitTypeInsn(CHECKCAST, "java/lang/Long"); mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false); }
            default -> mv.visitTypeInsn(CHECKCAST, "java/lang/String");
        }
    }
    static void trampolineBody(MethodVisitor mv, ClassNode owner, MethodNode dec) {
        Type[] at = Type.getArgumentTypes(dec.desc);
        for (int i = 0; i < at.length; i++) {
            mv.visitFieldInsn(GETSTATIC, "gd/Holder", "A", "[Ljava/lang/Object;");
            mv.visitLdcInsn(i); mv.visitInsn(AALOAD); unbox(mv, at[i]);
        }
        mv.visitMethodInsn(INVOKESTATIC, owner.name, dec.name, dec.desc, false);
        mv.visitFieldInsn(PUTSTATIC, "gd/Holder", "R", "Ljava/lang/String;");
    }
    int stackRuns = 0;
    String runStack(ClassNode owner, MethodNode dec, String callerCls, String callerM, Object[] args) {
        if (badSandbox.contains(owner.name) || ++stackRuns > 30000) return null;
        try {
            ClassNode st = stub(owner, dec, true);
            if (st == null) { badSandbox.add(owner.name); return null; }
            Loader l = new Loader();
            ClassNode h = new ClassNode(); h.version = V1_8; h.access = ACC_PUBLIC; h.name = "gd/Holder"; h.superName = "java/lang/Object";
            h.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, "A", "[Ljava/lang/Object;", null, null));
            h.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, "R", "Ljava/lang/String;", null, null));
            l.defs.put("gd.Holder", bytes(h));
            ClassNode T;
            if (callerCls.equals(owner.name)) T = st;
            else { T = new ClassNode(); T.version = V1_8; T.access = ACC_PUBLIC; T.name = callerCls; T.superName = "java/lang/Object"; }
            if (callerM.equals("<clinit>")) {
                MethodNode orig = null; for (MethodNode m : T.methods) if (m.name.equals("<clinit>")) orig = m;
                if (orig != null) orig.name = "gd$clinit";
                MethodNode ci = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
                if (orig != null) ci.visitMethodInsn(INVOKESTATIC, T.name, "gd$clinit", "()V", false);
                trampolineBody(ci, owner, dec); ci.visitInsn(RETURN); T.methods.add(ci);
            } else if (callerM.equals("<init>")) {
                MethodNode ci = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
                ci.visitVarInsn(ALOAD, 0); ci.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                trampolineBody(ci, owner, dec); ci.visitInsn(RETURN); T.methods.add(ci);
            } else {
                for (MethodNode m : T.methods) if (m.name.equals(callerM) && m.desc.equals("()V")) return null;
                MethodNode ci = new MethodNode(ACC_PUBLIC | ACC_STATIC, callerM, "()V", null, null);
                trampolineBody(ci, owner, dec); ci.visitInsn(RETURN); T.methods.add(ci);
            }
            if (T != st) l.defs.put(owner.name.replace('/', '.'), bytes(st));
            l.defs.put(T.name.replace('/', '.'), bytes(T));
            Class<?> hc = Class.forName("gd.Holder", true, l);
            hc.getField("A").set(null, args);
            Class<?> tc = Class.forName(T.name.replace('/', '.'), false, l);
            Object[] a = args;
            pool.submit(() -> {
                if (callerM.equals("<clinit>")) Class.forName(tc.getName(), true, l);
                else if (callerM.equals("<init>")) tc.getConstructor().newInstance();
                else tc.getMethod(callerM).invoke(null);
                return null;
            }).get(4, TimeUnit.SECONDS);
            Object r = hc.getField("R").get(null);
            return r instanceof String x ? x : null;
        } catch (Throwable t) { return null; }
    }

    void decryptStrings() {
        Map<String, MethodNode> cands = new HashMap<>(); Map<String, ClassNode> owners = new HashMap<>();
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) if (candidate(m)) { String k = c.name + "." + m.name + m.desc; cands.put(k, m); owners.put(k, c); }
        if (cands.isEmpty()) return;
        Map<String, String> cache = new HashMap<>();
        Set<String> removeFrom = new HashSet<>(); Map<String, Integer> useCount = new HashMap<>();
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) {
            for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
                AbstractInsnNode next = in.getNext();
                if (in instanceof MethodInsnNode mi && mi.getOpcode() == INVOKESTATIC) {
                    String key = mi.owner + "." + mi.name + mi.desc;
                    MethodNode dec = cands.get(key);
                    if (dec != null) {
                        Type[] at = Type.getArgumentTypes(mi.desc);
                        Object[] args = new Object[at.length]; AbstractInsnNode[] srcs = new AbstractInsnNode[at.length];
                        AbstractInsnNode p = in; boolean ok = true;
                        for (int k = at.length - 1; k >= 0 && ok; k--) {
                            p = prevReal(p);
                            if (p == null) { ok = false; break; }
                            Object v;
                            if (at[k].getDescriptor().equals("Ljava/lang/String;")) v = p instanceof LdcInsnNode l && l.cst instanceof String s ? s : null;
                            else { v = cst(p); if (v instanceof Integer iv && at[k].getSort() == Type.LONG) v = null; if (v instanceof Integer iv2) v = coerce(at[k], iv2); }
                            if (v == null || (at[k].getSort() == Type.LONG && !(v instanceof Long))) ok = false; else { args[k] = v; srcs[k] = p; }
                        }
                        if (ok && noLabelBetween(srcs[0], in)) {
                            String ck = key + Arrays.deepToString(args);
                            String res = cache.get(ck);
                            if (res == null && !cache.containsKey(ck)) {
                                if (stackDep(dec)) { ck = ck + "@" + c.name + "." + m.name; res = cache.get(ck); if (res == null && !cache.containsKey(ck)) { res = runStack(owners.get(key), dec, c.name, m.name, args); cache.put(ck, res); } }
                                else { res = run(owners.get(key), dec, args); cache.put(ck, res); }
                            }
                            if (res != null) {
                                for (AbstractInsnNode s : srcs) m.instructions.remove(s);
                                m.instructions.set(in, new LdcInsnNode(res)); strings++; useCount.merge(key, 1, Integer::sum);
                            }
                        }
                    }
                }
                in = next;
            }
        }
        // çözücü metotlar artık çağrılmıyorsa sil
        Set<String> still = new HashSet<>();
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) for (AbstractInsnNode i : m.instructions) if (i instanceof MethodInsnNode mi) still.add(mi.owner + "." + mi.name + mi.desc);
        for (String k : useCount.keySet()) if (!still.contains(k)) owners.get(k).methods.remove(cands.get(k));
    }
    static Object coerce(Type t, int v) {
        return switch (t.getSort()) { case Type.BYTE -> (byte) v; case Type.SHORT -> (short) v; case Type.CHAR -> (char) v; case Type.LONG -> null; default -> v; };
    }
    String run(ClassNode owner, MethodNode dec, Object[] args) {
        Method meth = sandbox(owner, dec);
        if (meth == null) return null;
        try {
            Object[] a = args.clone();
            Future<Object> f = pool.submit(() -> meth.invoke(null, a));
            Object r = f.get(3, TimeUnit.SECONDS);
            return r instanceof String s ? s : null;
        } catch (Throwable t) { return null; }
    }


    /* ============================================================ ZKM tarzı: <clinit> içinde çözülen static String[] */
    void decryptStaticArrays() {
        for (ClassNode c : new ArrayList<>(classes.values())) {
            MethodNode ci = null; for (MethodNode m : c.methods) if (m.name.equals("<clinit>")) ci = m;
            if (ci == null) continue;
            Set<String> arr = new HashSet<>();
            for (FieldNode f : c.fields) if ((f.access & ACC_STATIC) != 0 && f.desc.equals("[Ljava/lang/String;")) arr.add(f.name);
            if (arr.isEmpty()) continue;
            // başka metotlarda yazılan diziler güvenilmez
            for (MethodNode m : c.methods) if (m != ci) for (AbstractInsnNode i : m.instructions) if (i instanceof FieldInsnNode fi && fi.getOpcode() == PUTSTATIC && fi.owner.equals(c.name)) arr.remove(fi.name);
            if (arr.isEmpty()) continue;
            Frame<BasicValue>[] fr;
            try { fr = new Analyzer<>(new BasicInterpreter()).analyze(c.name, ci); } catch (Exception e) { continue; }
            AbstractInsnNode[] ins = ci.instructions.toArray();
            int cut = -1;
            for (int i = 0; i < ins.length; i++) {
                AbstractInsnNode in = ins[i];
                if (!safeInsn(in, c.name) || in.getOpcode() == RETURN) break;
                if (in instanceof FieldInsnNode fi && fi.getOpcode() == PUTSTATIC && fi.owner.equals(c.name) && arr.contains(fi.name)) {
                    int nx = i + 1; while (nx < ins.length && ins[nx].getOpcode() == -1) nx++;
                    if (nx < ins.length && fr[nx] != null && fr[nx].getStackSize() == 0) cut = i;
                }
            }
            if (cut < 0) continue;
            try {
                ClassNode st = stub(c, null, false);
                if (st == null) continue;
                st.methods.removeIf(m -> m.name.equals("<clinit>"));
                Map<LabelNode, LabelNode> lm = new HashMap<>(); for (AbstractInsnNode i : ins) if (i instanceof LabelNode l) lm.put(l, new LabelNode());
                MethodNode pre = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
                for (int i = 0; i <= cut; i++) pre.instructions.add(ins[i].clone(lm));
                pre.instructions.add(new InsnNode(RETURN));
                for (TryCatchBlockNode t : ci.tryCatchBlocks) if (pre.instructions.contains(lm.get(t.start)) && pre.instructions.contains(lm.get(t.end)) && pre.instructions.contains(lm.get(t.handler)))
                    pre.tryCatchBlocks.add(new TryCatchBlockNode(lm.get(t.start), lm.get(t.end), lm.get(t.handler), t.type));
                st.methods.add(pre);
                Loader l = new Loader(); l.defs.put(c.name.replace('/', '.'), bytes(st));
                Class<?> k = Class.forName(c.name.replace('/', '.'), false, l);
                pool.submit(() -> { Class.forName(k.getName(), true, l); return null; }).get(4, TimeUnit.SECONDS);
                Map<String, String[]> vals = new HashMap<>();
                for (String fn : arr) { try { Object v = k.getField(fn).get(null); if (v instanceof String[] sa) vals.put(fn, sa.clone()); } catch (Throwable t) { } }
                if (vals.isEmpty()) continue;
                for (ClassNode u : classes.values()) for (MethodNode m : u.methods) {
                    for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
                        AbstractInsnNode next = in.getNext();
                        if (in instanceof FieldInsnNode fi && fi.getOpcode() == GETSTATIC && fi.owner.equals(c.name) && vals.containsKey(fi.name) && !(u == c && m == ci)) {
                            AbstractInsnNode ix = nextReal(in), ld = ix == null ? null : nextReal(ix);
                            Object idx = cst(ix);
                            if (idx instanceof Integer n && ld != null && ld.getOpcode() == AALOAD && noLabelBetween(in, ld)) {
                                String[] sa = vals.get(fi.name);
                                if (n >= 0 && n < sa.length && sa[n] != null) {
                                    LdcInsnNode ln = new LdcInsnNode(sa[n]); m.instructions.set(in, ln); m.instructions.remove(ix); m.instructions.remove(ld); next = ln.getNext(); strings++;
                                }
                            }
                        }
                        in = next;
                    }
                }
            } catch (Throwable t) { /* bu sınıf atlanır */ }
        }
    }

    /* ============================================================ ZKM tarzı statik boolean opaque predicate alanları */
    int staticBools;
    void foldStaticBooleans() {
        Map<String, Integer> val = new HashMap<>(); Set<String> bad = new HashSet<>(); Set<String> cand = new HashSet<>();
        for (ClassNode c : classes.values()) for (FieldNode f : c.fields)
            if ((f.access & ACC_STATIC) != 0 && f.desc.equals("Z") && f.value == null) cand.add(c.name + "." + f.name);
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) for (AbstractInsnNode in : m.instructions) {
            if (!(in instanceof FieldInsnNode fi) || fi.getOpcode() != PUTSTATIC || !fi.desc.equals("Z")) continue;
            String k = fi.owner + "." + fi.name; if (!cand.contains(k)) continue;
            Object v = cst(prevReal(in));
            if (!m.name.equals("<clinit>") || !fi.owner.equals(c.name) || !(v instanceof Integer iv) || (val.containsKey(k) && !val.get(k).equals(iv))) { bad.add(k); continue; }
            if (val.containsKey(k)) bad.add(k); else val.put(k, iv); // birden fazla yazma: güvenilmez
        }
        for (String k : cand) { if (bad.contains(k)) continue; if (!val.containsKey(k)) { // hiç yazılmamış: yalnızca private ise varsayılan false
            String[] p = {k.substring(0, k.lastIndexOf('.')), k.substring(k.lastIndexOf('.') + 1)};
            boolean priv = classes.get(p[0]).fields.stream().anyMatch(f -> f.name.equals(p[1]) && (f.access & ACC_PRIVATE) != 0);
            if (priv) val.put(k, 0); } }
        if (val.isEmpty()) return;
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) {
            if (m.name.equals("<clinit>")) continue;
            for (AbstractInsnNode in = m.instructions.getFirst(); in != null; ) {
                AbstractInsnNode next = in.getNext();
                if (in instanceof FieldInsnNode fi && fi.getOpcode() == GETSTATIC && fi.desc.equals("Z") && val.containsKey(fi.owner + "." + fi.name) && !bad.contains(fi.owner + "." + fi.name)) {
                    m.instructions.set(in, push(val.get(fi.owner + "." + fi.name))); staticBools++;
                }
                in = next;
            }
        }
    }

    /* ============================================================ ana akış */
    void run(File in, File out) throws Exception {
        read(in);
        foldStaticBooleans(); decryptStaticArrays();
        // 1) statik string çözme (sayı katlamadan ÖNCE değil, sonra daha iyi: önce sabitleri sadeleştir)
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) safely(c, m);
        findProxies(); inlineProxies();
        decryptStrings();
        for (ClassNode c : classes.values()) for (MethodNode m : c.methods) safely(c, m); // çözülen sabitlerle ikinci tur
        pool.shutdownNow();
        write(out);
    }
    /** Dönüşüm bir metodu bozarsa (analiz hatası) o metodu eski haline döndür */
    void safely(ClassNode c, MethodNode m) {
        MethodNode backup = new MethodNode(m.access, m.name, m.desc, m.signature, m.exceptions.toArray(new String[0]));
        m.accept(backup);
        int f0 = folded, p0 = peep, b0 = branches, d0 = dead;
        try {
            method(c, m);
            new Analyzer<>(new BasicInterpreter()).analyze(c.name, m);
        } catch (Throwable t) {
            m.instructions = backup.instructions; m.tryCatchBlocks = backup.tryCatchBlocks; m.localVariables = backup.localVariables;
            folded = f0; peep = p0; branches = b0; dead = d0;
        }
    }

    void write(File out) throws IOException {
        try (ZipOutputStream zo = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out)))) {
            Set<String> seen = new HashSet<>();
            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                String n = e.getKey(); if (n.contains("..") || n.startsWith("/")) continue; // zip-slip koruması
                if (!seen.add(n)) continue;
                zo.putNextEntry(new ZipEntry(n)); zo.write(e.getValue()); zo.closeEntry();
            }
            for (ClassNode c : classes.values()) {
                byte[] b;
                try {
                    ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) { @Override protected String getCommonSuperClass(String a, String b2) { return "java/lang/Object"; } };
                    c.accept(w); b = w.toByteArray();
                } catch (Throwable t) {
                    b = original.get(c.name);
                }
                String n = c.name + ".class"; if (!seen.add(n)) continue;
                zo.putNextEntry(new ZipEntry(n)); zo.write(b); zo.closeEntry();
            }
        }
    }

    static String json(List<String> l) { StringBuilder sb = new StringBuilder("["); for (int i = 0; i < l.size(); i++) { if (i > 0) sb.append(','); sb.append('"').append(l.get(i).replace("\\", "\\\\").replace("\"", "\\\"")).append('"'); } return sb.append(']').toString(); }

    public static void main(String[] a) throws Exception {
        if (a.length > 1 && a[0].equals("--detect")) { System.out.println("STATS {\"detected\":" + json(fingerprint(new File(a[1]))) + "}"); return; }
        GenericDeobf g = new GenericDeobf();
        g.run(new File(a[0]), new File(a[1]));
        System.out.println("STATS {\"folded\":" + g.folded + ",\"peephole\":" + g.peep + ",\"branches\":" + g.branches + ",\"dead\":" + g.dead
                + ",\"staticBools\":" + g.staticBools + ",\"proxies\":" + g.proxies + ",\"strings\":" + g.strings + ",\"badEntries\":" + g.badEntries + ",\"classes\":" + g.classes.size() + "}");
        System.exit(0);
    }
}
