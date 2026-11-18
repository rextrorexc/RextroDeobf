import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * Bayt kodu seviyesinde Skidfuscator tarzı "anahtar değişkeni + saf yardımcı fonksiyon" akış obfuscation'ını çözer.
 *
 *  - saf (yalnız int aritmetiği yapan) static yardımcıları bulur ve kendisi çalıştırır
 *  - anahtar (state) yerel değişkenlerin değerini küme-sabit analiziyle bulur (çağrı noktalarındaki sabit parametreler dahil)
 *  - değeri bilinen guard / switch / if koşullarını katlar, ulaşılamayan kodu siler
 *  - artık kullanılmayan anahtar atamalarını siler
 * Sonuç jar'ı CFR'a verilir.
 *
 * Kullanım: java -cp asm*.jar;. SkidClean in.jar out.jar [sınıf-adı-regex]
 */
public class SkidClean {
    static final int CAP = 12;

    /* ------------------------------------------------------------------ değer alanı */
    static final class CV extends BasicValue {
        final Set<Integer> s;
        CV(Set<Integer> s) { super(Type.INT_TYPE); this.s = s; }
        static CV of(int v) { return new CV(new TreeSet<>(List.of(v))); }
        @Override public boolean equals(Object o) { return o instanceof CV c && c.s.equals(s); }
        @Override public int hashCode() { return s.hashCode(); }
    }

    static Set<Integer> known(BasicValue v) { return v instanceof CV c ? c.s : null; }

    /* ------------------------------------------------------------------ saf fonksiyonlar */
    static final class Pure {
        final MethodNode m; final int nargs;
        Pure(MethodNode m, int n) { this.m = m; this.nargs = n; }
    }

    final Map<String, Pure> pure = new HashMap<>();
    final Map<String, ClassNode> classes = new LinkedHashMap<>();
    final Map<String, Set<Integer>> seeds = new HashMap<>();   // "owner.name+desc#local" -> değerler
    final Set<String> badSeeds = new HashSet<>();
    int statFolded, statLoads, statRemoved, statMethods, statStores, statCalls;

    static boolean allowedPure(int op) {
        switch (op) {
            case -1: case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3: case ICONST_4: case ICONST_5:
            case BIPUSH: case SIPUSH: case LDC: case ILOAD: case ISTORE: case IINC:
            case IADD: case ISUB: case IMUL: case IDIV: case IREM: case INEG: case ISHL: case ISHR: case IUSHR: case IAND: case IOR: case IXOR:
            case I2B: case I2S: case I2C: case DUP: case POP: case SWAP: case IRETURN: case GOTO: case NOP:
            case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE:
            case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE:
                return true;
            default: return false;
        }
    }

    static String key(String owner, String name, String desc) { return owner + "." + name + desc; }

    void findPure() {
        pure.clear();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                if ((m.access & ACC_STATIC) == 0 || (m.access & ACC_ABSTRACT) != 0) continue;
                Type[] args = Type.getArgumentTypes(m.desc);
                if (Type.getReturnType(m.desc).getSort() != Type.INT || args.length == 0 || args.length > 3) continue;
                boolean ok = true;
                for (Type t : args) if (t.getSort() != Type.INT) ok = false;
                if (!ok) continue;
                int n = 0;
                for (AbstractInsnNode i : m.instructions) {
                    int op = i.getOpcode();
                    if (op == -1) continue;
                    n++;
                    if (!allowedPure(op) || (op == LDC && !(((LdcInsnNode) i).cst instanceof Integer))) { ok = false; break; }
                }
                if (ok && n > 0 && n < 120) pure.put(key(cn.name, m.name, m.desc), new Pure(m, args.length));
            }
        }
    }

    static Integer evalPure(Pure p, int[] args) {
        MethodNode m = p.m;
        AbstractInsnNode[] ins = m.instructions.toArray();
        Map<LabelNode, Integer> idx = new HashMap<>();
        for (int i = 0; i < ins.length; i++) if (ins[i] instanceof LabelNode l) idx.put(l, i);
        int[] loc = new int[Math.max(m.maxLocals, args.length) + 4];
        System.arraycopy(args, 0, loc, 0, args.length);
        int[] st = new int[64]; int sp = 0, pc = 0, steps = 0;
        while (pc < ins.length && steps++ < 20000) {
            AbstractInsnNode in = ins[pc++];
            int op = in.getOpcode();
            if (op == -1) continue;
            switch (op) {
                case ICONST_M1: st[sp++] = -1; break;
                case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3: case ICONST_4: case ICONST_5: st[sp++] = op - ICONST_0; break;
                case BIPUSH: case SIPUSH: st[sp++] = ((IntInsnNode) in).operand; break;
                case LDC: st[sp++] = (Integer) ((LdcInsnNode) in).cst; break;
                case ILOAD: st[sp++] = loc[((VarInsnNode) in).var]; break;
                case ISTORE: loc[((VarInsnNode) in).var] = st[--sp]; break;
                case IINC: loc[((IincInsnNode) in).var] += ((IincInsnNode) in).incr; break;
                case DUP: st[sp] = st[sp - 1]; sp++; break;
                case POP: sp--; break;
                case SWAP: { int t = st[sp - 1]; st[sp - 1] = st[sp - 2]; st[sp - 2] = t; break; }
                case NOP: break;
                case INEG: st[sp - 1] = -st[sp - 1]; break;
                case I2B: st[sp - 1] = (byte) st[sp - 1]; break;
                case I2S: st[sp - 1] = (short) st[sp - 1]; break;
                case I2C: st[sp - 1] = (char) st[sp - 1]; break;
                case IADD: case ISUB: case IMUL: case IDIV: case IREM: case ISHL: case ISHR: case IUSHR: case IAND: case IOR: case IXOR: {
                    int b = st[--sp], a = st[--sp];
                    Integer r = bin(op, a, b);
                    if (r == null) return null;
                    st[sp++] = r; break;
                }
                case GOTO: pc = idx.get(((JumpInsnNode) in).label); break;
                case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE: {
                    int a = st[--sp];
                    if (cmp1(op, a)) pc = idx.get(((JumpInsnNode) in).label);
                    break;
                }
                case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE: {
                    int b = st[--sp], a = st[--sp];
                    if (cmp2(op, a, b)) pc = idx.get(((JumpInsnNode) in).label);
                    break;
                }
                case IRETURN: return st[sp - 1];
                default: return null;
            }
        }
        return null;
    }

    static Integer bin(int op, int a, int b) {
        switch (op) {
            case IADD: return a + b;
            case ISUB: return a - b;
            case IMUL: return a * b;
            case IDIV: return b == 0 ? null : a / b;
            case IREM: return b == 0 ? null : a % b;
            case ISHL: return a << b;
            case ISHR: return a >> b;
            case IUSHR: return a >>> b;
            case IAND: return a & b;
            case IOR: return a | b;
            case IXOR: return a ^ b;
            default: return null;
        }
    }
    static boolean cmp1(int op, int a) {
        switch (op) {
            case IFEQ: return a == 0; case IFNE: return a != 0; case IFLT: return a < 0;
            case IFGE: return a >= 0; case IFGT: return a > 0; default: return a <= 0;
        }
    }
    static boolean cmp2(int op, int a, int b) {
        switch (op) {
            case IF_ICMPEQ: return a == b; case IF_ICMPNE: return a != b; case IF_ICMPLT: return a < b;
            case IF_ICMPGE: return a >= b; case IF_ICMPGT: return a > b; default: return a <= b;
        }
    }

    /* ------------------------------------------------------------------ yorumlayıcı */
    final class Interp extends BasicInterpreter {
        final ClassNode cn; final MethodNode mn; Set<Integer> tracked = new HashSet<>(); Map<Integer, Integer> paramVals = new HashMap<>();
        Interp(ClassNode cn, MethodNode mn) { super(ASM9); this.cn = cn; this.mn = mn; }

        @Override public BasicValue newParameterValue(boolean inst, int local, Type type) {
            if (type.getSort() == Type.INT && paramVals.containsKey(local)) return CV.of(paramVals.get(local));
            return super.newParameterValue(inst, local, type);
        }

        @Override public BasicValue copyOperation(AbstractInsnNode in, BasicValue v) throws AnalyzerException {
            if (in.getOpcode() == ISTORE && v instanceof CV && !tracked.contains(((VarInsnNode) in).var)) return BasicValue.INT_VALUE;
            return super.copyOperation(in, v);
        }

        @Override public BasicValue newOperation(AbstractInsnNode in) throws AnalyzerException {
            Integer c = constOf(in);
            return c != null ? CV.of(c) : super.newOperation(in);
        }

        @Override public BasicValue unaryOperation(AbstractInsnNode in, BasicValue v) throws AnalyzerException {
            Set<Integer> s = known(v);
            int op = in.getOpcode();
            if (s != null) {
                Set<Integer> r = new TreeSet<>();
                for (int a : s) {
                    switch (op) {
                        case INEG: r.add(-a); break;
                        case I2B: r.add((int) (byte) a); break;
                        case I2S: r.add((int) (short) a); break;
                        case I2C: r.add((int) (char) a); break;
                        case IINC: if (!tracked.contains(((IincInsnNode) in).var)) return BasicValue.INT_VALUE; r.add(a + ((IincInsnNode) in).incr); break;
                        default: r = null;
                    }
                    if (r == null) break;
                }
                if (r != null) return new CV(r);
            }
            return super.unaryOperation(in, v);
        }

        @Override public BasicValue binaryOperation(AbstractInsnNode in, BasicValue a, BasicValue b) throws AnalyzerException {
            Set<Integer> x = known(a), y = known(b);
            int op = in.getOpcode();
            if (x != null && y != null && op >= IADD && op <= IXOR && (op == IADD || op == ISUB || op == IMUL || op == IDIV || op == IREM
                    || op == ISHL || op == ISHR || op == IUSHR || op == IAND || op == IOR || op == IXOR)) {
                Set<Integer> r = new TreeSet<>();
                for (int p : x) for (int q : y) { Integer t = bin(op, p, q); if (t == null) return super.binaryOperation(in, a, b); r.add(t); }
                if (r.size() <= CAP) return new CV(r);
            }
            return super.binaryOperation(in, a, b);
        }

        @Override public BasicValue naryOperation(AbstractInsnNode in, List<? extends BasicValue> vals) throws AnalyzerException {
            if (in.getOpcode() == INVOKESTATIC) {
                MethodInsnNode mi = (MethodInsnNode) in;
                Pure p = pure.get(key(mi.owner, mi.name, mi.desc));
                if (p != null && vals.size() == p.nargs) {
                    List<Set<Integer>> sets = new ArrayList<>();
                    for (BasicValue v : vals) { Set<Integer> s = known(v); if (s == null) { sets = null; break; } sets.add(s); }
                    if (sets != null) {
                        Set<Integer> r = new TreeSet<>();
                        if (combos(p, sets, 0, new int[p.nargs], r) && r.size() <= CAP && !r.isEmpty()) return new CV(r);
                    }
                }
            }
            return super.naryOperation(in, vals);
        }

        boolean combos(Pure p, List<Set<Integer>> sets, int i, int[] cur, Set<Integer> out) {
            if (i == sets.size()) { Integer r = evalPure(p, cur.clone()); if (r == null) return false; out.add(r); return out.size() <= CAP; }
            for (int v : sets.get(i)) { cur[i] = v; if (!combos(p, sets, i + 1, cur, out)) return false; }
            return true;
        }

        @Override public BasicValue merge(BasicValue a, BasicValue b) {
            if (a instanceof CV x && b instanceof CV y) {
                if (x.s.containsAll(y.s)) return a;
                Set<Integer> u = new TreeSet<>(x.s); u.addAll(y.s);
                return u.size() > CAP ? BasicValue.INT_VALUE : new CV(u);
            }
            return super.merge(a, b);
        }
    }

    static Integer constOf(AbstractInsnNode in) {
        if (in == null) return null;
        int op = in.getOpcode();
        if (op >= ICONST_M1 && op <= ICONST_5) return op - ICONST_0;
        if (op == BIPUSH || op == SIPUSH) return ((IntInsnNode) in).operand;
        if (op == LDC && ((LdcInsnNode) in).cst instanceof Integer i) return i;
        return null;
    }

    static AbstractInsnNode pushInt(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, v);
        return new LdcInsnNode(v);
    }

    static boolean real(AbstractInsnNode i) { return i.getOpcode() != -1; }
    static AbstractInsnNode prevReal(AbstractInsnNode i) {
        AbstractInsnNode p = i.getPrevious();
        while (p != null && (p instanceof LineNumberNode || p instanceof FrameNode)) p = p.getPrevious();
        return p != null && real(p) ? p : null;
    }

    /* ------------------------------------------------------------------ anahtar yerelleri */
    Set<Integer> keyLocals(MethodNode m) {
        Map<Integer, Integer> cnt = new HashMap<>();
        for (AbstractInsnNode i : m.instructions) {
            if (i.getOpcode() != ISTORE) continue;
            AbstractInsnNode p = prevReal(i);
            if (p == null) continue;
            boolean upd = p.getOpcode() == IXOR
                    || (p.getOpcode() == INVOKESTATIC && pure.containsKey(key(((MethodInsnNode) p).owner, ((MethodInsnNode) p).name, ((MethodInsnNode) p).desc)));
            if (upd) cnt.merge(((VarInsnNode) i).var, 1, Integer::sum);
        }
        Set<Integer> r = new HashSet<>();
        for (var e : cnt.entrySet()) if (e.getValue() >= 2) r.add(e.getKey());
        return r;
    }

    /* ------------------------------------------------------------------ tohum parametreler */
    void collectSeeds() {
        seeds.clear(); badSeeds.clear();
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode i : m.instructions) {
                    if (!(i instanceof MethodInsnNode mi)) continue;
                    if (pure.containsKey(key(mi.owner, mi.name, mi.desc))) continue;
                    Type[] args = Type.getArgumentTypes(mi.desc);
                    if (args.length == 0) continue;
                    ClassNode target = classes.get(mi.owner);
                    if (target == null) continue;
                    int slot = mi.getOpcode() == INVOKESTATIC ? 0 : 1;
                    int last = -1;
                    for (int a = 0; a < args.length; a++) { if (a == args.length - 1) last = slot; slot += args[a].getSize(); }
                    if (args[args.length - 1].getSort() != Type.INT) continue;
                    String k = mi.name + mi.desc + "#" + last;
                    Integer c = constOf(prevReal(i));
                    if (c == null || Math.abs((long) c) < 65536) { badSeeds.add(k); continue; }
                    seeds.computeIfAbsent(k, x -> new TreeSet<>()).add(c);
                }
    }

    /* ------------------------------------------------------------------ metot sadeleştirme */
    boolean simplify(ClassNode cn, MethodNode mn) {
        if (mn.instructions.size() == 0 || (mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) return false;
        Set<Integer> keys = keyLocals(mn);
        boolean changed = peephole(mn);
        if (keys.isEmpty()) return changed;
        for (int round = 0; round < 10; round++) {
            Explore ex = exploreAll(cn, mn, keys);
            if (ex == null) { statAbort++; if (statAbort <= 25) System.err.println("abort: " + cn.name + "." + mn.name + mn.desc + " size=" + mn.instructions.size()); return changed; }
            boolean ch = false;
            AbstractInsnNode[] ins = ex.ins;
            for (int i = 0; i < ins.length; i++) {
                AbstractInsnNode in = ins[i];
                int op = in.getOpcode();
                if (op == -1) continue;
                if (!ex.reached[i]) { if (!Boolean.getBoolean("norm")) { mn.instructions.remove(in); statRemoved++; ch = true; } continue; }
                if (op == ILOAD && keys.contains(((VarInsnNode) in).var)) {
                    Set<Integer> vs = ex.loadVals.get(i);
                    if (vs != null && vs.size() == 1 && !vs.contains(null)) { mn.instructions.set(in, pushInt(vs.iterator().next())); statLoads++; ch = true; }
                } else if ((op >= IFEQ && op <= IFLE) || (op >= IF_ICMPEQ && op <= IF_ICMPLE)) {
                    Set<Integer> o = ex.outcome.get(i);
                    if (o != null && o.size() == 1) {
                        boolean taken = o.iterator().next() == 1;
                        boolean two = op >= IF_ICMPEQ;
                        InsnList rep = new InsnList();
                        rep.add(new InsnNode(two ? POP2 : POP));
                        if (taken) rep.add(new JumpInsnNode(GOTO, ((JumpInsnNode) in).label));
                        mn.instructions.insert(in, rep); mn.instructions.remove(in);
                        statFolded++; ch = true;
                    }
                } else if (op == TABLESWITCH || op == LOOKUPSWITCH) {
                    Set<Integer> o = ex.outcome.get(i);
                    if (o != null && o.size() == 1) {
                        LabelNode tg = ex.switchLabel.get(i);
                        if (tg != null) {
                            InsnList rep = new InsnList();
                            rep.add(new InsnNode(POP)); rep.add(new JumpInsnNode(GOTO, tg));
                            mn.instructions.insert(in, rep); mn.instructions.remove(in);
                            statFolded++; ch = true;
                        }
                    } else if (o != null && o.size() > 1) {
                        // katlanamayan switch: hiç kullanılmayan (silinecek) hedefleri kullanılan bir hedefe yönlendir
                        Map<AbstractInsnNode, Integer> p2 = new IdentityHashMap<>();
                        for (int q = 0; q < ins.length; q++) p2.put(ins[q], q);
                        LabelNode live = null;
                        for (int idx : o) if (idx >= 0 && idx < ins.length && ins[idx] instanceof LabelNode l) { live = l; break; }
                        if (live != null) {
                            if (in instanceof TableSwitchInsnNode t) {
                                for (int q = 0; q < t.labels.size(); q++) if (!o.contains(p2.get(t.labels.get(q)))) t.labels.set(q, live);
                                if (!o.contains(p2.get(t.dflt))) t.dflt = live;
                            } else {
                                LookupSwitchInsnNode l = (LookupSwitchInsnNode) in;
                                for (int q = 0; q < l.labels.size(); q++) if (!o.contains(p2.get(l.labels.get(q)))) l.labels.set(q, live);
                                if (!o.contains(p2.get(l.dflt))) l.dflt = live;
                            }
                        }
                    }
                }
            }
            // ulaşılamayan handler'lı try-catch'leri sil
            Map<AbstractInsnNode, Integer> pos = new IdentityHashMap<>();
            for (int i = 0; i < ins.length; i++) pos.put(ins[i], i);
            Iterator<TryCatchBlockNode> it = mn.tryCatchBlocks.iterator();
            while (it.hasNext()) {
                TryCatchBlockNode t = it.next();
                Integer hp = pos.get(t.handler);
                boolean any = false;
                for (AbstractInsnNode i = t.start; i != null && i != t.end; i = i.getNext()) if (real(i)) { any = true; break; }
                if (!any || (hp != null && !ex.handlerHit[hp])) { it.remove(); ch = true; }
            }
            if (!Boolean.getBoolean("nopeep") && peephole(mn)) ch = true;
            if (!Boolean.getBoolean("nodead") && dropDead(mn, keys)) ch = true;
            if (!ch) break;
            changed = true;
        }
        return changed;
    }

    /** metodun anahtar parametresi için çağrı noktalarındaki her sabit değer ayrı keşfedilir, sonuçlar birleştirilir */
    Explore exploreAll(ClassNode cn, MethodNode mn, Set<Integer> keys) {
        int loc = (mn.access & ACC_STATIC) != 0 ? 0 : 1;
        int seedLoc = -1; Set<Integer> vals = null;
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            if (t.getSort() == Type.INT) {
                String k = mn.name + mn.desc + "#" + loc;
                Set<Integer> s = seeds.get(k);
                if (s != null && !badSeeds.contains(k) && s.size() <= 8) { seedLoc = loc; vals = s; }
            }
            loc += t.getSize();
        }
        if (vals == null) return explore(cn, mn, keys, new HashMap<>());
        Explore all = null;
        for (int v : vals) {
            Explore e = explore(cn, mn, keys, new HashMap<>(Map.of(seedLoc, v)));
            if (e == null) return null;
            if (all == null) { all = e; continue; }
            for (int i = 0; i < all.reached.length; i++) { all.reached[i] |= e.reached[i]; all.handlerHit[i] |= e.handlerHit[i]; }
            for (var en : e.loadVals.entrySet()) all.loadVals.computeIfAbsent(en.getKey(), x -> new HashSet<>()).addAll(en.getValue());
            for (var en : e.outcome.entrySet()) all.outcome.computeIfAbsent(en.getKey(), x -> new HashSet<>()).addAll(en.getValue());
            for (var en : e.switchLabel.entrySet()) {
                LabelNode old = all.switchLabel.putIfAbsent(en.getKey(), en.getValue());
                if (old != null && old != en.getValue()) all.outcome.get(en.getKey()).add(-1 - all.outcome.get(en.getKey()).size());
            }
        }
        return all;
    }

    /* ------------------------------------------------------------------ açık-durumlu (yol duyarlı) keşif */
    static final class Explore {
        AbstractInsnNode[] ins;
        boolean[] reached, handlerHit;
        Map<Integer, Set<Integer>> loadVals = new HashMap<>();   // ILOAD k -> değerler (null = bilinmiyor)
        Map<Integer, Set<Integer>> outcome = new HashMap<>();    // koşullu atlama -> {0,1}; switch -> hedef komut indeksi
        Map<Integer, LabelNode> switchLabel = new HashMap<>();
    }

    Explore explore(ClassNode cn, MethodNode mn, Set<Integer> keys, Map<Integer, Integer> pv) {
        Interp interp = new Interp(cn, mn);
        interp.paramVals = pv;
        Set<Integer> tracked = new HashSet<>(keys);
        int loc = (mn.access & ACC_STATIC) != 0 ? 0 : 1;
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            if (t.getSort() == Type.INT && pv.containsKey(loc)) tracked.add(loc);
            loc += t.getSize();
        }
        interp.tracked = tracked;

        Explore ex = new Explore();
        ex.ins = mn.instructions.toArray();
        int n = ex.ins.length;
        ex.reached = new boolean[n]; ex.handlerHit = new boolean[n];
        Map<AbstractInsnNode, Integer> pos = new IdentityHashMap<>();
        for (int i = 0; i < n; i++) pos.put(ex.ins[i], i);

        int nl = mn.maxLocals + 2;
        Frame<BasicValue> init = new Frame<>(nl, mn.maxStack + 4);
        try {
            int l = 0;
            boolean inst = (mn.access & ACC_STATIC) == 0;
            if (inst) init.setLocal(l++, interp.newParameterValue(true, 0, Type.getObjectType(cn.name)));
            for (Type t : Type.getArgumentTypes(mn.desc)) {
                init.setLocal(l, interp.newParameterValue(inst, l, t)); l++;
                if (t.getSize() == 2) { init.setLocal(l, interp.newEmptyValue(l)); l++; }
            }
            while (l < nl) { init.setLocal(l, interp.newEmptyValue(l)); l++; }
            init.setReturn(interp.newReturnTypeValue(Type.getReturnType(mn.desc)));
        } catch (Exception e) { return null; }

        int tc = mn.tryCatchBlocks.size();
        int[] ts = new int[tc], te = new int[tc], th = new int[tc];
        for (int t = 0; t < tc; t++) {
            TryCatchBlockNode b = mn.tryCatchBlocks.get(t);
            ts[t] = pos.get(b.start); te[t] = pos.get(b.end); th[t] = pos.get(b.handler);
        }

        Deque<Object[]> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(new Object[]{0, init});
        int steps = 0;
        List<Integer> trackedList = new ArrayList<>(tracked);
        Collections.sort(trackedList);
        try {
            while (!work.isEmpty()) {
                Object[] w = work.poll();
                int pc = (Integer) w[0];
                @SuppressWarnings("unchecked") Frame<BasicValue> f = (Frame<BasicValue>) w[1];
                while (pc < n) {
                    if (++steps > 800000) return null;
                    AbstractInsnNode in = ex.ins[pc];
                    int op = in.getOpcode();
                    if (op == -1) {
                        if (in instanceof LabelNode) {
                            String sg = pc + "|" + sig(f, trackedList);
                            if (!seen.add(sg)) break;
                        }
                        ex.reached[pc] = true;
                        pc++;
                        continue;
                    }
                    ex.reached[pc] = true;
                    if (canThrow(in)) {
                        for (int t = 0; t < tc; t++) if (pc >= ts[t] && pc < te[t]) {
                            Frame<BasicValue> h = new Frame<>(f);
                            h.clearStack();
                            h.push(interp.newValue(Type.getObjectType("java/lang/Throwable")));
                            ex.handlerHit[th[t]] = true;
                            work.add(new Object[]{th[t], h});
                        }
                    }
                    if (op == ILOAD && tracked.contains(((VarInsnNode) in).var)) {
                        Integer v = single(f.getLocal(((VarInsnNode) in).var));
                        ex.loadVals.computeIfAbsent(pc, x -> new HashSet<>()).add(v);
                    }
                    if ((op >= IFEQ && op <= IFLE) || (op >= IF_ICMPEQ && op <= IF_ICMPLE)) {
                        boolean two = op >= IF_ICMPEQ;
                        Integer a = single(f.getStack(f.getStackSize() - 1));
                        Integer b = two ? single(f.getStack(f.getStackSize() - 2)) : Integer.valueOf(0);
                        f.execute(in, interp);
                        LabelNode tgt = ((JumpInsnNode) in).label;
                        Set<Integer> o = ex.outcome.computeIfAbsent(pc, x -> new HashSet<>());
                        if (a != null && b != null) {
                            boolean t = two ? cmp2(op, b, a) : cmp1(op, a);
                            o.add(t ? 1 : 0);
                            if (t) { pc = pos.get(tgt); } else { pc++; }
                            continue;
                        }
                        o.add(0); o.add(1);
                        work.add(new Object[]{pos.get(tgt), new Frame<>(f)});
                        pc++;
                        continue;
                    }
                    if (op == TABLESWITCH || op == LOOKUPSWITCH) {
                        Integer v = single(f.getStack(f.getStackSize() - 1));
                        f.execute(in, interp);
                        List<LabelNode> all = new ArrayList<>();
                        if (in instanceof TableSwitchInsnNode t) { all.addAll(t.labels); all.add(t.dflt); }
                        else { LookupSwitchInsnNode l = (LookupSwitchInsnNode) in; all.addAll(l.labels); all.add(l.dflt); }
                        Set<Integer> o = ex.outcome.computeIfAbsent(pc, x -> new HashSet<>());
                        if (v != null) {
                            LabelNode tg = switchTarget(in, v);
                            o.add(pos.get(tg)); ex.switchLabel.put(pc, tg);
                            pc = pos.get(tg);
                            continue;
                        }
                        for (LabelNode l : all) { o.add(pos.get(l)); work.add(new Object[]{pos.get(l), new Frame<>(f)}); }
                        break;
                    }
                    if (op == GOTO) { pc = pos.get(((JumpInsnNode) in).label); continue; }
                    if (op == ATHROW || (op >= IRETURN && op <= RETURN)) break;
                    if (op == JSR || op == RET) return null;
                    if (op == IFNULL || op == IFNONNULL || (op >= IF_ACMPEQ && op <= IF_ACMPNE)) {
                        f.execute(in, interp);
                        work.add(new Object[]{pos.get(((JumpInsnNode) in).label), new Frame<>(f)});
                        pc++;
                        continue;
                    }
                    f.execute(in, interp);
                    pc++;
                }
            }
        } catch (Exception | StackOverflowError e) { return null; }
        return ex;
    }

    static Integer single(BasicValue v) {
        if (v instanceof CV c && c.s.size() == 1) return c.s.iterator().next();
        return null;
    }

    static String sig(Frame<BasicValue> f, List<Integer> tracked) {
        StringBuilder sb = new StringBuilder();
        for (int k : tracked) { Integer v = single(f.getLocal(k)); sb.append(v == null ? "?" : v.toString()).append(','); }
        sb.append('|');
        for (int i = 0; i < f.getStackSize(); i++) { Integer v = single(f.getStack(i)); sb.append(v == null ? "." : v.toString()).append(','); }
        return sb.toString();
    }

    /** istisna kenarı yalnızca gerçekten fırlatabilecek komutlardan handler'a gider (anahtar değeri tam kalır) */
    static boolean canThrow(AbstractInsnNode in) {
        int op = in.getOpcode();
        if (op == -1) return false;
        if (op <= 20) return false;                       // nop, aconst, iconst.., ldc (sınıf sabiti hariç aşağıda)
        if (op >= ILOAD && op <= ALOAD) return false;
        if (op >= ISTORE && op <= ASTORE) return false;
        if (op >= POP && op <= SWAP) return false;
        if (op >= IADD && op <= DREM && op != IDIV && op != LDIV && op != IREM && op != LREM) return false;
        if (op >= INEG && op <= DNEG) return false;
        if (op >= ISHL && op <= LXOR) return false;
        if (op == IINC) return false;
        if (op >= I2L && op <= I2S) return false;
        if (op >= LCMP && op <= DCMPG) return false;
        if (op >= IFEQ && op <= JSR) return false;
        if (op == GOTO) return false;
        if (op == IFNULL || op == IFNONNULL) return false;
        return true;
    }

    static LabelNode switchTarget(AbstractInsnNode in, int v) {
        if (in instanceof TableSwitchInsnNode t) return v >= t.min && v <= t.max ? t.labels.get(v - t.min) : t.dflt;
        LookupSwitchInsnNode l = (LookupSwitchInsnNode) in;
        int k = l.keys.indexOf(v);
        return k >= 0 ? l.labels.get(k) : l.dflt;
    }

    boolean peephole(MethodNode mn) {
        boolean any = false, ch = true;
        while (ch) {
            ch = false;
            for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
                int op = in.getOpcode();
                if (op == -1) continue;
                AbstractInsnNode a = prevReal(in);
                if (isBin(op)) {
                    AbstractInsnNode b = a == null ? null : prevReal(a);
                    Integer cb = constOf(b), ca = constOf(a);
                    if (cb != null && ca != null && isBin(op)) {
                        Integer r = bin(op, cb, ca);
                        if (r != null) { replace(mn, b, in, pushInt(r)); ch = true; break; }
                    }
                } else if (op == INEG || op == I2B || op == I2S || op == I2C) {
                    Integer ca = constOf(a);
                    if (ca != null) {
                        int r = op == INEG ? -ca : op == I2B ? (byte) (int) ca : op == I2S ? (short) (int) ca : (char) (int) ca;
                        replace(mn, a, in, pushInt(r)); ch = true; break;
                    }
                } else if (op == INVOKESTATIC && ((MethodInsnNode) in).owner.equals("java/lang/Integer") && ((MethodInsnNode) in).name.equals("parseInt")
                        && ((MethodInsnNode) in).desc.equals("(Ljava/lang/String;)I")) {
                    if (a instanceof LdcInsnNode l && l.cst instanceof String str) {
                        try { replace(mn, a, in, pushInt(Integer.parseInt(str))); statCalls++; ch = true; break; } catch (NumberFormatException e) { /* bırak */ }
                    }
                } else if (op == INVOKESTATIC) {
                    MethodInsnNode mi = (MethodInsnNode) in;
                    Pure p = pure.get(key(mi.owner, mi.name, mi.desc));
                    if (p == null) continue;
                    int[] args = new int[p.nargs];
                    AbstractInsnNode first = null, cur = a;
                    boolean ok = true;
                    for (int k = p.nargs - 1; k >= 0; k--) {
                        Integer c = constOf(cur);
                        if (c == null) { ok = false; break; }
                        args[k] = c; first = cur; cur = prevReal(cur);
                    }
                    if (ok) {
                        Integer r = evalPure(p, args);
                        if (r != null) { replace(mn, first, in, pushInt(r)); statCalls++; ch = true; break; }
                    }
                } else if (op == POP) {
                    if (constOf(a) != null) { replace(mn, a, in, null); ch = true; break; }
                    if (a != null && a.getOpcode() == ILOAD) { replace(mn, a, in, null); ch = true; break; }
                } else if (op == POP2) {
                    AbstractInsnNode b = a == null ? null : prevReal(a);
                    if (a != null && b != null && (constOf(a) != null || a.getOpcode() == ILOAD) && (constOf(b) != null || b.getOpcode() == ILOAD)) {
                        replace(mn, b, in, null); ch = true; break;
                    }
                } else if (op >= IF_ICMPEQ && op <= IF_ICMPLE) {
                    AbstractInsnNode b = a == null ? null : prevReal(a);
                    Integer ca = constOf(a), cb = constOf(b);
                    if (ca != null && cb != null) {
                        boolean t = cmp2(op, cb, ca);
                        replace(mn, b, in, t ? new JumpInsnNode(GOTO, ((JumpInsnNode) in).label) : null);
                        statFolded++; ch = true; break;
                    }
                } else if (op >= IFEQ && op <= IFLE) {
                    Integer ca = constOf(a);
                    if (ca != null) {
                        boolean t = cmp1(op, ca);
                        replace(mn, a, in, t ? new JumpInsnNode(GOTO, ((JumpInsnNode) in).label) : null);
                        statFolded++; ch = true; break;
                    }
                } else if (op == TABLESWITCH || op == LOOKUPSWITCH) {
                    Integer ca = constOf(a);
                    if (ca != null) { replace(mn, a, in, new JumpInsnNode(GOTO, switchTarget(in, ca))); statFolded++; ch = true; break; }
                } else if (op == NOP) { mn.instructions.remove(in); ch = true; break; }
            }
            if (ch) any = true;
        }
        return any;
    }

    static boolean isBin(int op) { return op == IADD || op == ISUB || op == IMUL || op == IDIV || op == IREM || op == ISHL || op == ISHR || op == IUSHR || op == IAND || op == IOR || op == IXOR; }

    /** [from..to] aralığındaki gerçek komutları siler; rep varsa yerine koyar (to'nun yerine) */
    static void replace(MethodNode mn, AbstractInsnNode from, AbstractInsnNode to, AbstractInsnNode rep) {
        AbstractInsnNode cur = from;
        List<AbstractInsnNode> del = new ArrayList<>();
        while (true) {
            del.add(cur);
            if (cur == to) break;
            cur = cur.getNext();
        }
        if (rep != null) mn.instructions.insertBefore(from, rep);
        for (AbstractInsnNode d : del) if (real(d) || d instanceof LineNumberNode) mn.instructions.remove(d);
    }

    /** artık hiç okunmayan anahtar yerellerine yazan "ISTORE" komutlarını POP'a çevir; saf ifadeleri sil */
    boolean dropDead(MethodNode mn, Set<Integer> keys) {
        boolean ch = false;
        Set<Integer> loaded = new HashSet<>();
        for (AbstractInsnNode i : mn.instructions) {
            if (i.getOpcode() == ILOAD) loaded.add(((VarInsnNode) i).var);
            if (i instanceof IincInsnNode ii) loaded.add(ii.var);
        }
        for (AbstractInsnNode i = mn.instructions.getFirst(); i != null; ) {
            AbstractInsnNode nx = i.getNext();
            if (i.getOpcode() == ISTORE && keys.contains(((VarInsnNode) i).var) && !loaded.contains(((VarInsnNode) i).var)) {
                mn.instructions.set(i, new InsnNode(POP)); statStores++; ch = true;
            }
            i = nx;
        }
        // POP + saf ifade zincirini sil
        boolean again = true;
        while (again) {
            again = false;
            for (AbstractInsnNode i = mn.instructions.getFirst(); i != null; i = i.getNext()) {
                if (i.getOpcode() != POP) continue;
                AbstractInsnNode start = pureExprStart(i);
                if (start != null) { replace(mn, start, i, null); ch = true; again = true; break; }
            }
        }
        return ch;
    }

    /** POP'un tükettiği değeri üreten saf komut dizisinin başı (yoksa null) */
    AbstractInsnNode pureExprStart(AbstractInsnNode pop) {
        int need = 1;
        AbstractInsnNode cur = prevReal(pop), first = null;
        while (cur != null && need > 0) {
            int op = cur.getOpcode();
            int produced, consumed;
            if (constOf(cur) != null || op == ILOAD) { produced = 1; consumed = 0; }
            else if (isBin(op)) { produced = 1; consumed = 2; }
            else if (op == INEG || op == I2B || op == I2S || op == I2C) { produced = 1; consumed = 1; }
            else if (op == INVOKESTATIC && pure.containsKey(key(((MethodInsnNode) cur).owner, ((MethodInsnNode) cur).name, ((MethodInsnNode) cur).desc))) {
                produced = 1; consumed = pure.get(key(((MethodInsnNode) cur).owner, ((MethodInsnNode) cur).name, ((MethodInsnNode) cur).desc)).nargs;
            } else return null;
            need = need - produced + consumed;
            first = cur;
            cur = need > 0 ? prevReal(cur) : cur;
        }
        return need == 0 ? first : null;
    }

    boolean dropEmptyTryCatch(MethodNode mn, Frame<BasicValue>[] fr, AbstractInsnNode[] ins) {
        boolean ch = false;
        Map<AbstractInsnNode, Integer> pos = new IdentityHashMap<>();
        for (int i = 0; i < ins.length; i++) pos.put(ins[i], i);
        Iterator<TryCatchBlockNode> it = mn.tryCatchBlocks.iterator();
        while (it.hasNext()) {
            TryCatchBlockNode t = it.next();
            boolean any = false;
            for (AbstractInsnNode i = t.start; i != null && i != t.end; i = i.getNext()) if (real(i)) { any = true; break; }
            Integer hp = pos.get(t.handler);
            if (!any || (hp != null && fr[hp] == null)) { it.remove(); ch = true; }
        }
        return ch;
    }

    /* ------------------------------------------------------------------ anahtar parametrelerini sil */
    int statParams, statAbort;

    record Call(MethodNode in, MethodInsnNode insn) {}

    /** Sonu "int" olan, hiç okunmayan ve tüm çağrı noktalarında büyük sabit geçilen parametreleri tanım ve çağrılardan siler */
    void stripKeyParams() {
        Map<String, List<MethodNode>> decls = new HashMap<>();
        Map<String, List<ClassNode>> owners = new HashMap<>();
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods) {
                Type[] a = Type.getArgumentTypes(m.desc);
                if (a.length == 0 || a[a.length - 1].getSort() != Type.INT || m.name.equals("<clinit>") || m.name.equals("main")) continue;
                String k = m.name + m.desc;
                decls.computeIfAbsent(k, x -> new ArrayList<>()).add(m);
                owners.computeIfAbsent(k, x -> new ArrayList<>()).add(cn);
            }
        Map<String, List<Call>> calls = new HashMap<>();
        Set<String> blocked = new HashSet<>();
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode i : m.instructions) {
                    if (i instanceof MethodInsnNode mi) {
                        String k = mi.name + mi.desc;
                        if (!decls.containsKey(k)) continue;
                        Integer c = constOf(prevReal(mi));
                        if (!classes.containsKey(mi.owner) || c == null || Math.abs((long) c) < 65536) blocked.add(k);
                        else calls.computeIfAbsent(k, x -> new ArrayList<>()).add(new Call(m, mi));
                    } else if (i instanceof InvokeDynamicInsnNode d) {
                        for (Object o : d.bsmArgs) if (o instanceof Handle h) blocked.add(h.getName() + h.getDesc());
                    }
                }
        for (var e : decls.entrySet()) {
            String k = e.getKey();
            if (blocked.contains(k) || !calls.containsKey(k)) continue;
            List<MethodNode> ms = e.getValue();
            boolean ok = true;
            for (int d = 0; d < ms.size() && ok; d++) {
                MethodNode m = ms.get(d);
                if ((m.access & ACC_NATIVE) != 0) { ok = false; break; }
                Type[] a = Type.getArgumentTypes(m.desc);
                int slot = (m.access & ACC_STATIC) != 0 ? 0 : 1;
                for (int p = 0; p < a.length - 1; p++) slot += a[p].getSize();
                for (AbstractInsnNode i : m.instructions) {
                    if ((i.getOpcode() == ILOAD || i.getOpcode() == ISTORE) && ((VarInsnNode) i).var == slot) { ok = false; break; }
                    if (i instanceof IincInsnNode ii && ii.var == slot) { ok = false; break; }
                }
                String nd = Type.getMethodDescriptor(Type.getReturnType(m.desc), Arrays.copyOf(a, a.length - 1));
                for (MethodNode o : owners.get(k).get(d).methods) if (o != m && o.name.equals(m.name) && o.desc.equals(nd)) ok = false;
            }
            if (!ok) continue;
            for (MethodNode m : ms) {
                Type[] a = Type.getArgumentTypes(m.desc);
                Type[] b = Arrays.copyOf(a, a.length - 1);
                int slot = (m.access & ACC_STATIC) != 0 ? 0 : 1;
                for (Type t : b) slot += t.getSize();
                m.desc = Type.getMethodDescriptor(Type.getReturnType(m.desc), b);
                m.signature = null;
                m.visibleParameterAnnotations = null; m.invisibleParameterAnnotations = null;
                if (m.parameters != null && m.parameters.size() == a.length) m.parameters.remove(m.parameters.size() - 1);
                if (m.localVariables != null) { final int sl = slot; m.localVariables.removeIf(lv -> lv.index == sl && lv.desc.equals("I")); }
                statParams++;
            }
            for (Call c : calls.get(k)) {
                AbstractInsnNode p = prevReal(c.insn());
                Type[] a = Type.getArgumentTypes(c.insn().desc);
                c.insn().desc = Type.getMethodDescriptor(Type.getReturnType(c.insn().desc), Arrays.copyOf(a, a.length - 1));
                c.in().instructions.remove(p);
            }
        }
    }

    /* ------------------------------------------------------------------ jar işleme */
    void run(File in, File out, Pattern filter) throws Exception {
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
                classes.put(cn.name, cn);
            } catch (Exception ex) { /* bozuk sınıf */ }
        }
        findPure();
        System.err.println("saf fonksiyon: " + pure.size());
        for (int pass = 0; pass < 6; pass++) {
            collectSeeds();
            int before = statFolded + statLoads + statRemoved + statCalls + statStores;
            for (ClassNode cn : classes.values()) {
                if (!filter.matcher(cn.name.replace('/', '.')).find()) continue;
                for (MethodNode m : cn.methods) if (simplify(cn, m)) statMethods++;
            }
            System.err.println("tur " + pass + ": folded=" + statFolded + " loads=" + statLoads + " removed=" + statRemoved);
            if (statFolded + statLoads + statRemoved + statCalls + statStores == before) break;
        }
        if (!Boolean.getBoolean("nostrip")) stripKeyParams();
        try (ZipOutputStream zo = new ZipOutputStream(new FileOutputStream(out))) {
            for (var e : raw.entrySet()) {
                byte[] data = e.getValue();
                String n = e.getKey();
                if (n.endsWith(".class")) {
                    String cname = n.substring(0, n.length() - 6);
                    ClassNode cn = classes.get(cname);
                    if (cn != null && filter.matcher(cname.replace('/', '.')).find()) {
                        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                        cn.accept(cw);
                        data = cw.toByteArray();
                    }
                }
                zo.putNextEntry(new ZipEntry(n));
                zo.write(data);
                zo.closeEntry();
            }
        }
        System.out.println("STATS {\"methods\":" + statMethods + ",\"folded\":" + statFolded + ",\"keyLoads\":" + statLoads
                + ",\"unreachable\":" + statRemoved + ",\"pureCalls\":" + statCalls + ",\"deadStores\":" + statStores + ",\"keyParams\":" + statParams + ",\"pureFns\":" + pure.size() + "}");
    }

    /** yığın / tür tutarlılığı denetimi (hata ayıklama): java SkidClean --verify jar [regex] */
    static void verify(File jar, Pattern f) throws Exception {
        int bad = 0, total = 0;
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(jar))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (!e.getName().endsWith(".class")) continue;
                ClassNode cn = new ClassNode();
                new ClassReader(z.readAllBytes()).accept(cn, ClassReader.SKIP_FRAMES);
                if (!f.matcher(cn.name.replace('/', '.')).find()) continue;
                for (MethodNode m : cn.methods) {
                    if (m.instructions.size() == 0) continue;
                    total++;
                    try { new Analyzer<>(new BasicVerifier()).analyze(cn.name, m); }
                    catch (AnalyzerException ex) { bad++; if (bad <= 15) System.out.println("BAD " + cn.name + "." + m.name + m.desc + " : " + ex.getMessage()); }
                }
            }
        }
        System.out.println("verify: " + bad + " / " + total);
    }

    public static void main(String[] a) throws Exception {
        if (a.length > 1 && a[0].equals("--verify")) { verify(new File(a[1]), Pattern.compile(a.length > 2 ? a[2] : "^(?!.*\\blibs\\b)")); return; }
        Pattern f = Pattern.compile(a.length > 2 ? a[2] : "^(?!.*\\blibs\\b)");
        new SkidClean().run(new File(a[0]), new File(a[1]), f);
    }
}
