import java.io.*; import java.util.*; import java.nio.charset.StandardCharsets; import javax.crypto.*; import javax.crypto.spec.*;
public class Dump { public static void main(String[] a) throws Exception {
 try (DataInputStream in = new DataInputStream(new FileInputStream(a[0])); PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(a[1]), StandardCharsets.UTF_8))) {
  if (in.readInt()!=1213484879) throw new Error("magic"); int n=in.readInt();
  for (int i=0;i<n;i++){ String e=in.readUTF(),no=in.readUTF(),l=in.readUTF(),r=in.readUTF();
   byte[] x=Base64.getDecoder().decode(l), y=Base64.getDecoder().decode(r), k=new byte[x.length]; for(int j=0;j<k.length;j++)k[j]=(byte)(x[j]^y[j]);
   Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(2,new SecretKeySpec(k,"AES"),new GCMParameterSpec(128,Base64.getDecoder().decode(no)));
   String s=new String(c.doFinal(Base64.getDecoder().decode(e)),StandardCharsets.UTF_8);
   out.print(i+"\t"+Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8))+"\n"); }
  System.out.println(n);
 } } }
