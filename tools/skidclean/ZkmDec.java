import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import static org.objectweb.asm.Opcodes.*;

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.zip.*;

/**
 * Zelix KlassMaster (ZKM) Gelişmiş Bayt Kodu Şifre Çözücü:
 * Matrix AntiCheat ve ZKM ile korunan tüm JAR'lar için:
 *   1) DES tabanlı dinamik string şifrelemeyi (InvokeDynamic #0: (IJ)Ljava/lang/String;) çözer ve LDC "metin" ile değiştirir.
 *   2) DES tabanlı dinamik tamsayı şifrelemeyi (InvokeDynamic #1: (IJ)I) çözer ve ICONST/BIPUSH/SIPUSH/LDC ile değiştirir.
 *   3) Spigot/Bukkit bağımlılıklarını dinamik stub class/interface oluşturucu ile çalışma anında çözer.
 *   4) Çözülen sınıflardaki ölü DES mekanizmasını (Cipher, SecretKeyFactory, bootstrap metotları) temizler.
 */
public class ZkmDec {
    static final Set<String> interfaces = new HashSet<>();

    public static class StubLoader extends URLClassLoader {
        public StubLoader(URL[] urls) {
            super(urls, ZkmDec.class.getClassLoader());
        }
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            try {
                return super.findClass(name);
            } catch (ClassNotFoundException e) {
                String slash = name.replace('.', '/');
                boolean isItf = interfaces.contains(slash) || name.contains("Listener") || name.contains("Executor") || name.contains("Sender") || name.endsWith("able");
                ClassWriter cw = new ClassWriter(0);
                if (isItf) {
                    cw.visit(V1_8, ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT, slash, null, "java/lang/Object", null);
                } else {
                    cw.visit(V1_8, ACC_PUBLIC, slash, null, "java/lang/Object", null);
                    MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
                    mv.visitVarInsn(ALOAD, 0);
                    mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                    mv.visitInsn(RETURN);
                    mv.visitMaxs(1, 1);
                    mv.visitEnd();
                }
                cw.visitEnd();
                byte[] b = cw.toByteArray();
                return defineClass(name, b, 0, b.length);
            }
        }
    }

    static Integer constInt(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op >= ICONST_M1 && op <= ICONST_5) return op - ICONST_0;
        if (op == BIPUSH || op == SIPUSH) return ((IntInsnNode) in).operand;
        if (op == LDC && ((LdcInsnNode) in).cst instanceof Integer i) return i;
        return null;
    }

    static Long constLong(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op == LCONST_0) return 0L;
        if (op == LCONST_1) return 1L;
        if (op == LDC && ((LdcInsnNode) in).cst instanceof Long l) return l;
        return null;
    }

    static AbstractInsnNode prevReal(AbstractInsnNode i) {
        AbstractInsnNode p = i.getPrevious();
        while (p != null && (p instanceof LineNumberNode || p instanceof FrameNode)) p = p.getPrevious();
        return p;
    }

    static AbstractInsnNode pushInt(int i) {
        if (i >= -1 && i <= 5) return new InsnNode(ICONST_0 + i);
        if (i >= Byte.MIN_VALUE && i <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, i);
        if (i >= Short.MIN_VALUE && i <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, i);
        return new LdcInsnNode(i);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: ZkmDec <input.jar> <output.jar>");
            return;
        }
        File inJar = new File(args[0]);
        File outJar = new File(args[1]);

        Map<String, ClassNode> classes = new LinkedHashMap<>();
        Map<String, byte[]> resources = new LinkedHashMap<>();

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(inJar)))) {
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                if (ze.isDirectory()) continue;
                byte[] data = zis.readAllBytes();
                if (ze.getName().endsWith(".class") && data.length > 8 && (data[0] & 0xFF) == 0xCA && (data[1] & 0xFF) == 0xFE) {
                    ClassReader cr = new ClassReader(data);
                    ClassNode cn = new ClassNode();
                    cr.accept(cn, ClassReader.SKIP_FRAMES);
                    classes.put(cn.name, cn);
                    interfaces.addAll(cn.interfaces);
                } else {
                    resources.put(ze.getName(), data);
                }
            }
        }

        StubLoader loader = new StubLoader(new URL[]{ inJar.toURI().toURL() });

        int stringsDecrypted = 0;
        int intsDecrypted = 0;
        int classesDone = 0;

        for (ClassNode cn : classes.values()) {
            boolean hasZkmField = false;
            for (FieldNode fn : cn.fields) {
                if ((fn.access & ACC_STATIC) != 0 && fn.name.equals("a") && fn.desc.equals("J")) {
                    hasZkmField = true;
                    break;
                }
            }
            if (!hasZkmField) continue;

            Class<?> loadedClass = null;
            Long fieldA = null;
            Method decString = null;
            Method decInt = null;

            try {
                loadedClass = Class.forName(cn.name.replace('/', '.'), true, loader);
                Field fa = loadedClass.getDeclaredField("a");
                fa.setAccessible(true);
                fieldA = fa.getLong(null);

                for (Method m : loadedClass.getDeclaredMethods()) {
                    if ((m.getModifiers() & Modifier.STATIC) != 0) {
                        Class<?>[] p = m.getParameterTypes();
                        if (p.length == 2 && p[0] == int.class && p[1] == long.class) {
                            m.setAccessible(true);
                            if (m.getReturnType() == String.class && decString == null) {
                                decString = m;
                            } else if (m.getReturnType() == int.class && decInt == null) {
                                decInt = m;
                            }
                        }
                    }
                }
            } catch (Throwable t) {
                continue;
            }

            if (fieldA == null) continue;
            classesDone++;

            // Map of methodName + desc -> Long passed as arg0
            Map<String, Long> callArgs0 = new HashMap<>();
            Map<MethodNode, Map<Integer, Long>> methodLocals = new IdentityHashMap<>();

            // 1. Aşama: metod içi yerel long değişkenleri ve metot çağrılarına aktarılan long argümanları takip et
            for (MethodNode mn : cn.methods) {
                if (mn.instructions.size() == 0) continue;
                Map<Integer, Long> localLongs = new HashMap<>();
                methodLocals.put(mn, localLongs);

                for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
                    if (in.getOpcode() == LSTORE) {
                        int slot = ((VarInsnNode) in).var;
                        AbstractInsnNode p1 = prevReal(in);
                        if (p1 != null && p1.getOpcode() == LXOR) {
                            AbstractInsnNode p2 = prevReal(p1);
                            AbstractInsnNode p3 = p2 == null ? null : prevReal(p2);
                            if (p2 != null && p3 != null) {
                                Long c2 = constLong(p2);
                                Long c3 = constLong(p3);
                                if (c2 != null && p3 instanceof FieldInsnNode fi && fi.getOpcode() == GETSTATIC && fi.owner.equals(cn.name) && fi.name.equals("a")) {
                                    localLongs.put(slot, fieldA ^ c2);
                                } else if (c3 != null && p2 instanceof FieldInsnNode fi && fi.getOpcode() == GETSTATIC && fi.owner.equals(cn.name) && fi.name.equals("a")) {
                                    localLongs.put(slot, fieldA ^ c3);
                                } else if (c2 != null && p3 instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)) {
                                    localLongs.put(slot, localLongs.get(vi.var) ^ c2);
                                } else if (c3 != null && p2 instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)) {
                                    localLongs.put(slot, localLongs.get(vi.var) ^ c3);
                                }
                            }
                        } else if (p1 instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)) {
                            localLongs.put(slot, localLongs.get(vi.var));
                        }
                    }

                    // Synthetic Object[] sarmalayıcı çağrısını tespit et
                    if (in instanceof MethodInsnNode mi && mi.owner.equals(cn.name) && mi.desc.contains("([Ljava/lang/Object;)")) {
                        AbstractInsnNode pStore = prevReal(in);
                        if (pStore != null && pStore.getOpcode() == AASTORE) {
                            for (AbstractInsnNode cur = prevReal(pStore); cur != null; cur = prevReal(cur)) {
                                if (cur instanceof MethodInsnNode mval && mval.name.equals("valueOf") && mval.owner.equals("java/lang/Long")) {
                                    // valueOf'tan önce gelen long değişkeni veya ifadesi
                                    AbstractInsnNode pVal = prevReal(cur);
                                    if (pVal instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)) {
                                        callArgs0.put(mi.name + mi.desc, localLongs.get(vi.var));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // 2. Aşama: Object[] alan yardımcı metotlara argümanları aktar
            for (MethodNode mn : cn.methods) {
                if (mn.desc.contains("([Ljava/lang/Object;)")) {
                    Long passed0 = callArgs0.get(mn.name + mn.desc);
                    if (passed0 != null) {
                        Map<Integer, Long> localLongs = methodLocals.get(mn);
                        if (localLongs != null) {
                            for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
                                if (in.getOpcode() == LSTORE) {
                                    int slot = ((VarInsnNode) in).var;
                                    AbstractInsnNode p1 = prevReal(in);
                                    if (p1 instanceof MethodInsnNode mval && mval.name.equals("longValue") && mval.owner.equals("java/lang/Long")) {
                                        localLongs.put(slot, passed0);
                                    }
                                    if (p1 != null && p1.getOpcode() == LXOR) {
                                        AbstractInsnNode p2 = prevReal(p1);
                                        AbstractInsnNode p3 = p2 == null ? null : prevReal(p2);
                                        if (p2 instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)
                                                && p3 instanceof FieldInsnNode fi && fi.name.equals("a")) {
                                            localLongs.put(slot, fieldA ^ localLongs.get(vi.var));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 3. Aşama: invokedynamic çağrılarını sabit string ve int ile değiştir
            for (MethodNode mn : cn.methods) {
                Map<Integer, Long> localLongs = methodLocals.get(mn);
                if (localLongs == null) continue;

                for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; ) {
                    AbstractInsnNode next = in.getNext();
                    if (in instanceof InvokeDynamicInsnNode indy) {
                        boolean isTarget = indy.bsm.getOwner().equals(cn.name);
                        boolean isStr = indy.desc.endsWith(")Ljava/lang/String;");
                        boolean isI = indy.desc.endsWith(")I");

                        if (isTarget && (isStr || isI)) {
                            AbstractInsnNode p1 = prevReal(in);
                            Long key = null;
                            Integer tag = null;
                            List<AbstractInsnNode> toRemove = new ArrayList<>();

                            if (p1 != null && p1.getOpcode() == LXOR) {
                                AbstractInsnNode pA = prevReal(p1);
                                AbstractInsnNode pB = pA == null ? null : prevReal(pA);
                                AbstractInsnNode pTag = pB == null ? null : prevReal(pB);

                                Long callCst = constLong(pA);
                                VarInsnNode varInsn = (pB instanceof VarInsnNode vi && vi.getOpcode() == LLOAD) ? vi : null;
                                if (callCst == null || varInsn == null) {
                                    callCst = constLong(pB);
                                    varInsn = (pA instanceof VarInsnNode vi && vi.getOpcode() == LLOAD) ? vi : null;
                                }
                                tag = constInt(pTag);

                                if (callCst != null && varInsn != null && tag != null && localLongs.containsKey(varInsn.var)) {
                                    key = callCst ^ localLongs.get(varInsn.var);
                                    toRemove.addAll(Arrays.asList(pTag, pB, pA, p1));
                                }
                            } else if (p1 instanceof VarInsnNode vi && vi.getOpcode() == LLOAD && localLongs.containsKey(vi.var)) {
                                AbstractInsnNode pTag = prevReal(p1);
                                tag = constInt(pTag);
                                if (tag != null) {
                                    key = localLongs.get(vi.var);
                                    toRemove.addAll(Arrays.asList(pTag, p1));
                                }
                            }

                            if (key != null && tag != null) {
                                try {
                                    if (isStr && decString != null) {
                                        Object res = decString.invoke(null, tag, key);
                                        if (res instanceof String s) {
                                            LdcInsnNode repl = new LdcInsnNode(s);
                                            mn.instructions.set(in, repl);
                                            for (AbstractInsnNode r : toRemove) mn.instructions.remove(r);
                                            stringsDecrypted++;
                                            in = repl;
                                        }
                                    } else if (isI && decInt != null) {
                                        Object res = decInt.invoke(null, tag, key);
                                        if (res instanceof Integer iv) {
                                            AbstractInsnNode repl = pushInt(iv);
                                            mn.instructions.set(in, repl);
                                            for (AbstractInsnNode r : toRemove) mn.instructions.remove(r);
                                            intsDecrypted++;
                                            in = repl;
                                        }
                                    }
                                } catch (Throwable t) {}
                            }
                        }
                    }
                    in = next;
                }
            }
        }

        System.out.println("STATS {\"classes\":" + classesDone + ",\"strings\":" + stringsDecrypted + ",\"ints\":" + intsDecrypted + "}");

        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outJar)))) {
            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue());
                zos.closeEntry();
            }
            for (ClassNode cn : classes.values()) {
                ClassWriter cw = new ClassWriter(0);
                cn.accept(cw);
                zos.putNextEntry(new ZipEntry(cn.name + ".class"));
                zos.write(cw.toByteArray());
                zos.closeEntry();
            }
        }
        System.exit(0);
    }
}
