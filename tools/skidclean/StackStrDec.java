import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.*;
import java.util.zip.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * "Yığın izi anahtarlı" string şifrelemesini (static String m(byte,char,char,char,int,int,int) + new Throwable().getStackTrace()[1])
 * bayt kodu seviyesinde çözer ve çağrıları LDC "düz metin" ile değiştirir. Adlandırma / CFR öncesinde, ORİJİNAL sınıf-metot adlarıyla çalışmalıdır
 * (anahtar çağıran sınıf+metot adının hash'inden türüyor).
 *
 * Çözücü yalnızca çıkarılmış küçük bir "stub" sınıfta (aynı adla, ayrı class loader) ve beyaz listeli API'lerle çalıştırılır;
 * jar'ın başka hiçbir kodu çalıştırılmaz.
 */
public class StackStrDec {
    static final Set<String> WL = new HashSet<>(Arrays.asList("java/lang/String", "java/lang/Throwable", "java/lang/StackTraceElement", "java/lang/Object",
            "java/lang/Integer", "java/lang/Character", "java/lang/StringBuilder", "java/lang/Boolean", "java/util/Arrays", "java/lang/Math", "java/lang/Long", "java/lang/Byte", "java/lang/Short"));

    final Map<String, ClassNode> classes = new LinkedHashMap<>();
    int decrypted = 0, classesDone = 0, skipped = 0;

    public static class Rec { public static final Map<Integer, String> R = new HashMap<>(); public static void add(String s, int tag) { R.put(tag, s); } }

    static class Loader extends ClassLoader {
        final Map<String, byte[]> defs = new HashMap<>();
        Loader() { super(ClassLoader.getPlatformClassLoader()); }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            byte[] b = defs.get(n);
            if (b == null) throw new ClassNotFoundException(n);
            return defineClass(n, b, 0, b.length);
        }
    }

    static boolean isDecryptMethod(MethodNode m) {
        if ((m.access & ACC_STATIC) == 0) return false;
        Type r = Type.getReturnType(m.desc);
        if (!r.getDescriptor().equals("Ljava/lang/String;")) return false;
        for (Type t : Type.getArgumentTypes(m.desc)) if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) return false;
        if (Type.getArgumentTypes(m.desc).length < 2) return false;
        boolean st = false;
        for (AbstractInsnNode i : m.instructions) if (i instanceof MethodInsnNode mi && mi.name.equals("getStackTrace") && mi.owner.equals("java/lang/Throwable")) st = true;
        return st;
    }

    static Integer constOf(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op >= ICONST_M1 && op <= ICONST_5) return op - ICONST_0;
        if (op == BIPUSH || op == SIPUSH) return ((IntInsnNode) in).operand;
        if (op == LDC && ((LdcInsnNode) in).cst instanceof Integer i) return i;
        return null;
    }
    static AbstractInsnNode prevReal(AbstractInsnNode i) {
        AbstractInsnNode p = i.getPrevious();
        while (p != null && (p instanceof LineNumberNode || p instanceof FrameNode)) p = p.getPrevious();
        return p;
    }

    /** whitelist dışı çağrıları etkisizleştirilmiş clinit kopyası; her çözücü çağrısından sonra sonucu Rec'e kaydeder */
    boolean sanitizeClinit(ClassNode src, MethodNode clinit, MethodNode dec, MethodNode out, Map<AbstractInsnNode, Integer> tags) {
        InsnList l = new InsnList();
        Map<LabelNode, LabelNode> lm = new IdentityHashMap<>();
        for (AbstractInsnNode i = clinit.instructions.getFirst(); i != null; i = i.getNext()) if (i instanceof LabelNode ln) lm.put(ln, new LabelNode());
        for (AbstractInsnNode i = clinit.instructions.getFirst(); i != null; i = i.getNext()) {
            if (i instanceof LabelNode ln) { l.add(lm.get(ln)); continue; }
            if (i instanceof LineNumberNode || i instanceof FrameNode) continue;
            if (i instanceof MethodInsnNode mi) {
                if (mi.owner.equals(src.name) && mi.name.equals(dec.name) && mi.desc.equals(dec.desc)) {
                    l.add(new MethodInsnNode(mi.getOpcode(), mi.owner, mi.name, mi.desc, mi.itf));
                    l.add(new InsnNode(DUP));
                    Integer tag = tags.get(mi);
                    l.add(new LdcInsnNode(tag == null ? -1 : tag));
                    l.add(new MethodInsnNode(INVOKESTATIC, "StackStrDec$Rec", "add", "(Ljava/lang/String;I)V", false));
                    continue;
                }
                if (!WL.contains(mi.owner)) {                        // başka sınıfa çağrı: argümanları at, varsayılan değer koy
                    Type[] args = Type.getArgumentTypes(mi.desc);
                    for (int a = args.length - 1; a >= 0; a--) l.add(new InsnNode(args[a].getSize() == 2 ? POP2 : POP));
                    if (mi.getOpcode() != INVOKESTATIC) l.add(new InsnNode(POP));
                    pushDefault(l, Type.getReturnType(mi.desc));
                    continue;
                }
            } else if (i instanceof FieldInsnNode fi && !fi.owner.equals(src.name)) {
                Type t = Type.getType(fi.desc);
                if (fi.getOpcode() == GETSTATIC) pushDefault(l, t);
                else if (fi.getOpcode() == PUTSTATIC) l.add(new InsnNode(t.getSize() == 2 ? POP2 : POP));
                else if (fi.getOpcode() == GETFIELD) { l.add(new InsnNode(POP)); pushDefault(l, t); }
                else { l.add(new InsnNode(t.getSize() == 2 ? POP2 : POP)); l.add(new InsnNode(POP)); }
                continue;
            } else if (i instanceof TypeInsnNode ti && ti.getOpcode() == NEW && !WL.contains(ti.desc)) { l.add(new InsnNode(ACONST_NULL)); continue; }
            else if (i instanceof TypeInsnNode ti2 && (ti2.getOpcode() == CHECKCAST || ti2.getOpcode() == INSTANCEOF) && !WL.contains(ti2.desc) && !ti2.desc.startsWith("[")) { if (ti2.getOpcode() == INSTANCEOF) { l.add(new InsnNode(POP)); l.add(new InsnNode(ICONST_0)); } continue; }
            else if (i instanceof TypeInsnNode ti3 && ti3.getOpcode() == ANEWARRAY && !WL.contains(ti3.desc) && !ti3.desc.equals(src.name)) { l.add(new TypeInsnNode(ANEWARRAY, "java/lang/Object")); continue; }
            else if (i instanceof InvokeDynamicInsnNode) return false;
            AbstractInsnNode c = i.clone(lm);
            l.add(c);
        }
        out.instructions = l;
        for (TryCatchBlockNode t : clinit.tryCatchBlocks) out.tryCatchBlocks.add(new TryCatchBlockNode(lm.get(t.start), lm.get(t.end), lm.get(t.handler), t.type));
        return true;
    }

    static void pushDefault(InsnList l, Type t) {
        switch (t.getSort()) {
            case Type.VOID: break;
            case Type.LONG: l.add(new InsnNode(LCONST_0)); break;
            case Type.FLOAT: l.add(new InsnNode(FCONST_0)); break;
            case Type.DOUBLE: l.add(new InsnNode(DCONST_0)); break;
            case Type.OBJECT: case Type.ARRAY: l.add(new InsnNode(ACONST_NULL)); break;
            default: l.add(new InsnNode(ICONST_0));
        }
    }

    boolean processClass(ClassNode cn) throws Exception {
        MethodNode dec = null;
        for (MethodNode m : cn.methods) if (isDecryptMethod(m)) { dec = m; break; }
        if (dec == null) { if (System.getProperty("dbg") != null) System.err.println("ret false #1 " + cn.name); return false; }
        Type[] ptypes = Type.getArgumentTypes(dec.desc);
        // çağrı noktaları
        class Site { MethodNode caller; MethodInsnNode call; int[] args; int tag; AbstractInsnNode first; }
        List<Site> sites = new ArrayList<>();
        Map<AbstractInsnNode, Integer> tags = new IdentityHashMap<>();
        for (MethodNode m : cn.methods) for (AbstractInsnNode i : m.instructions) {
            if (!(i instanceof MethodInsnNode mi) || mi.getOpcode() != INVOKESTATIC || !mi.owner.equals(cn.name) || !mi.name.equals(dec.name) || !mi.desc.equals(dec.desc)) continue;
            int[] a = new int[ptypes.length];
            AbstractInsnNode p = i, first = i; boolean ok = true;
            for (int k = ptypes.length - 1; k >= 0; k--) {
                p = prevReal(p);
                List<Integer> casts = new ArrayList<>();
                while (p != null && (p.getOpcode() == I2B || p.getOpcode() == I2C || p.getOpcode() == I2S)) { casts.add(p.getOpcode()); p = prevReal(p); }
                Integer c = constOf(p);
                if (c == null) { ok = false; break; }
                int v = c;
                for (int ci = casts.size() - 1; ci >= 0; ci--) { int op = casts.get(ci); v = op == I2B ? (byte) v : op == I2C ? (char) v : (short) v; }
                a[k] = v; first = p;
            }
            if (!ok) continue;
            Site s = new Site(); s.caller = m; s.call = mi; s.args = a; s.tag = sites.size(); s.first = first;
            sites.add(s); tags.put(mi, s.tag);
        }
        if (sites.isEmpty()) { if (System.getProperty("dbg") != null) System.err.println("ret false #2 " + cn.name); return false; }

        // stub sınıfı
        ClassNode stub = new ClassNode();
        stub.version = V1_6; stub.access = ACC_PUBLIC | ACC_SUPER; stub.name = cn.name; stub.superName = "java/lang/Object";
        for (FieldNode f : cn.fields) if ((f.access & ACC_STATIC) != 0) stub.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, f.name, f.desc, null, null));
        MethodNode decCopy = new MethodNode(ACC_PUBLIC | ACC_STATIC, dec.name, dec.desc, null, null);
        // çözücü gövdesi beyaz liste denetiminden geçmeli
        for (AbstractInsnNode i : dec.instructions) {
            if (i instanceof MethodInsnNode mi && !WL.contains(mi.owner) && !mi.owner.equals(cn.name)) { if (System.getProperty("dbg") != null) System.err.println("ret false #3 " + cn.name); return false; }
            if (i instanceof InvokeDynamicInsnNode) { if (System.getProperty("dbg") != null) System.err.println("ret false #4 " + cn.name); return false; }
            if (i instanceof FieldInsnNode fi && !fi.owner.equals(cn.name)) { if (System.getProperty("dbg") != null) System.err.println("ret false #5 " + cn.name); return false; }
        }
        dec.accept(decCopy); decCopy.access = ACC_PUBLIC | ACC_STATIC;
        // dec içindeki kendi sınıfını çağıran başka yardımcılar varsa vazgeç
        for (AbstractInsnNode i : decCopy.instructions) if (i instanceof MethodInsnNode mi && mi.owner.equals(cn.name)) { if (System.getProperty("dbg") != null) System.err.println("ret false #6 " + cn.name); return false; }
        stub.methods.add(decCopy);

        MethodNode clinit = cn.methods.stream().filter(m -> m.name.equals("<clinit>")).findFirst().orElse(null);
        if (clinit != null) {
            MethodNode c2 = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
            if (!sanitizeClinit(cn, clinit, dec, c2, tags)) { if (System.getProperty("dbg") != null) System.err.println("ret false #7 " + cn.name); return false; }
            stub.methods.add(c2);
        }
        // çağıran metot adları
        Set<String> callerNames = new LinkedHashSet<>();
        for (Site s : sites) callerNames.add(s.caller.name);
        for (String name : callerNames) {
            if (name.equals("<clinit>") || name.equals(dec.name)) continue;
            if (name.equals("<init>")) {
                MethodNode k = new MethodNode(ACC_PUBLIC, "<init>", dec.desc.replace(")Ljava/lang/String;", ")V"), null, null);
                k.visitVarInsn(ALOAD, 0); k.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                int slot = 1;
                for (Type t : ptypes) { k.visitVarInsn(t.getOpcode(ILOAD), slot); slot += t.getSize(); }
                k.visitMethodInsn(INVOKESTATIC, cn.name, dec.name, dec.desc, false);
                k.visitFieldInsn(PUTSTATIC, cn.name, "$RESULT", "Ljava/lang/String;");
                k.visitInsn(RETURN); stub.methods.add(k);
            } else {
                MethodNode k = new MethodNode(ACC_PUBLIC | ACC_STATIC, name, dec.desc, null, null);
                int slot = 0;
                for (Type t : ptypes) { k.visitVarInsn(t.getOpcode(ILOAD), slot); slot += t.getSize(); }
                k.visitMethodInsn(INVOKESTATIC, cn.name, dec.name, dec.desc, false);
                k.visitInsn(ARETURN); stub.methods.add(k);
            }
        }
        stub.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, "$RESULT", "Ljava/lang/String;", null, null));
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        try { stub.accept(cw); } catch (Exception e) { { if (System.getProperty("dbg") != null) System.err.println("ret false #8 " + cn.name); return false; } }
        Loader ld = new Loader();
        ld.defs.put(cn.name.replace('/', '.'), cw.toByteArray());
        // Rec sınıfı
        ClassWriter rw = new ClassWriter(0);
        rw.visit(V1_6, ACC_PUBLIC | ACC_SUPER, "StackStrDec$Rec", null, "java/lang/Object", null);
        rw.visitField(ACC_PUBLIC | ACC_STATIC, "R", "Ljava/util/HashMap;", null, null).visitEnd();
        MethodVisitor ci = rw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        ci.visitCode(); ci.visitTypeInsn(NEW, "java/util/HashMap"); ci.visitInsn(DUP); ci.visitMethodInsn(INVOKESPECIAL, "java/util/HashMap", "<init>", "()V", false);
        ci.visitFieldInsn(PUTSTATIC, "StackStrDec$Rec", "R", "Ljava/util/HashMap;"); ci.visitInsn(RETURN); ci.visitMaxs(2, 0); ci.visitEnd();
        MethodVisitor mv = rw.visitMethod(ACC_PUBLIC | ACC_STATIC, "add", "(Ljava/lang/String;I)V", null, null);
        mv.visitCode(); mv.visitFieldInsn(GETSTATIC, "StackStrDec$Rec", "R", "Ljava/util/HashMap;"); mv.visitVarInsn(ILOAD, 1);
        mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false); mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/HashMap", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false); mv.visitInsn(POP);
        mv.visitInsn(RETURN); mv.visitMaxs(3, 2); mv.visitEnd(); rw.visitEnd();
        ld.defs.put("StackStrDec$Rec", rw.toByteArray());

        Map<Integer, String> results = new HashMap<>();
        try {
            Class<?> sc = Class.forName(cn.name.replace('/', '.'), true, ld);
            @SuppressWarnings("unchecked") Map<Integer, String> recMap = (Map<Integer, String>) Class.forName("StackStrDec$Rec", true, ld).getField("R").get(null);
            for (Site s : sites) {
                if (s.caller.name.equals("<clinit>")) { String r = recMap.get(s.tag); if (r != null) results.put(s.tag, r); continue; }
                Object[] av = new Object[ptypes.length];
                for (int k = 0; k < ptypes.length; k++) av[k] = box(ptypes[k], s.args[k]);
                Class<?>[] pc = new Class<?>[ptypes.length];
                for (int k = 0; k < ptypes.length; k++) pc[k] = cls(ptypes[k]);
                try {
                    if (s.caller.name.equals("<init>")) {
                        Constructor<?> ct = sc.getConstructor(pc); ct.newInstance(av);
                        Object r = sc.getField("$RESULT").get(null); if (r != null) results.put(s.tag, (String) r);
                    } else {
                        Method m = sc.getMethod(s.caller.name, pc); Object r = m.invoke(null, av); if (r != null) results.put(s.tag, (String) r);
                    }
                } catch (Throwable t) { if (System.getProperty("dbg") != null) System.err.println("site " + cn.name + "." + s.caller.name + " : " + (t.getCause() != null ? t.getCause() : t)); }
            }
        } catch (Throwable t) { if (System.getProperty("dbg") != null) { System.err.println("class fail " + cn.name + " : " + t); t.printStackTrace(); } { if (System.getProperty("dbg") != null) System.err.println("ret false #9 " + cn.name); return false; } }

        // çağrıları LDC'ye çevir
        int n = 0;
        for (Site s : sites) {
            String r = results.get(s.tag);
            if (r == null || r.length() > 60000) continue;
            InsnList list = s.caller.instructions;
            for (AbstractInsnNode p = s.first; ; ) {
                AbstractInsnNode nx = p.getNext();
                boolean last = p == s.call;
                if (last) { list.set(p, new LdcInsnNode(r)); break; }
                list.remove(p);
                p = nx;
            }
            n++;
        }
        decrypted += n;
        return n > 0;
    }

    public static class Recorder { public static final Map<Integer, String> R = new HashMap<>(); public static void add(String s, int t) { R.put(t, s); } }

    static Object box(Type t, int v) {
        switch (t.getSort()) {
            case Type.BYTE: return (byte) v; case Type.CHAR: return (char) v; case Type.SHORT: return (short) v;
            case Type.BOOLEAN: return v != 0; default: return v;
        }
    }
    static Class<?> cls(Type t) {
        switch (t.getSort()) {
            case Type.BYTE: return byte.class; case Type.CHAR: return char.class; case Type.SHORT: return short.class;
            case Type.BOOLEAN: return boolean.class; default: return int.class;
        }
    }

    void run(File in, File out) throws Exception {
        Map<String, byte[]> raw = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(in))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) if (!e.isDirectory()) raw.put(e.getName(), z.readAllBytes());
        }
        for (var e : raw.entrySet()) {
            if (!e.getKey().endsWith(".class")) continue;
            try { ClassNode cn = new ClassNode(); new ClassReader(e.getValue()).accept(cn, ClassReader.SKIP_FRAMES); classes.put(cn.name, cn); } catch (Exception ex) { }
        }
        Set<String> changed = new HashSet<>();
        for (ClassNode cn : classes.values()) {
            try { if (processClass(cn)) { changed.add(cn.name); classesDone++; } } catch (Throwable t) { skipped++; }
        }
        if (!changed.isEmpty()) {
            try (ZipOutputStream zo = new ZipOutputStream(new FileOutputStream(out))) {
                for (var e : raw.entrySet()) {
                    byte[] data = e.getValue();
                    if (e.getKey().endsWith(".class")) {
                        String cname = e.getKey().substring(0, e.getKey().length() - 6);
                        if (changed.contains(cname)) { ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS); classes.get(cname).accept(cw); data = cw.toByteArray(); }
                    }
                    zo.putNextEntry(new ZipEntry(e.getKey())); zo.write(data); zo.closeEntry();
                }
            }
        }
        System.out.println("STATS {\"strings\":" + decrypted + ",\"classes\":" + classesDone + ",\"skipped\":" + skipped + "}");
    }

    public static void main(String[] a) throws Exception { new StackStrDec().run(new File(a[0]), new File(a[1])); }
}
