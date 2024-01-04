package Hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Hash {
    public byte[] H1(int id, String response, long ramdom) {
        byte[] result;
        try {
            long random=ramdom;     // 64
            String input = id + " " + response;   //以空格分隔拼接在一起形成新字符串input
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] mes1 = md.digest(input.getBytes());  //H1(ID,R) 128

            byte[] bytes=new byte[8];
            for (int i = 7; i >=0 ; i--) {
                bytes[i]=(byte) (random & 0xFF);
                random>>=8;
            }
            byte[] mes2 = bytes;  //random 128

            byte[] newA=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            byte[] newB=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            //System.out.println(mes1.length+"              "+mes2.length);
            System.arraycopy(mes1,0,newA,0,mes1.length);
            System.arraycopy(mes2,0,newB,0,mes2.length);
            //System.out.println(mes2+"?");
            //System.out.println(mes2);
            result = new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            for (int i = 0; i < (mes1.length > mes2.length ? mes1.length : mes2.length); i++) {
                result[i] = (byte) (newA[i] ^ newB[i]);
            }
            //System.out.println("id:"+id+"r:"+response+"==r="+mes2+"==pid="+result+"==id+r"+mes1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return result;
    }

    public byte[] H1(int id,String response,byte[] pid) {
        byte[] result;
        try {

            String input = id + " " + response;
            //System.out.println(input);
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] mes1 = md.digest(input.getBytes(StandardCharsets.UTF_8));  //H1(ID,R)
            //System.out.println(byteTO(mes1));
            byte[] bytes=pid;
            byte[] mes2 = bytes;  //random
            byte[] newA=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            byte[] newB=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            //System.out.println(mes1.length+"   "+mes2.length);
            System.arraycopy(mes1,0,newA,0,mes1.length);
            System.arraycopy(mes2,0,newB,0,mes2.length);
            //System.out.println();
            result = new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            for (int i = 0; i < (mes1.length > mes2.length ? mes1.length : mes2.length); i++) {
                result[i] = (byte) (newA[i] ^ newB[i]);
            }
            //
            //System.out.println(id+"r=="+byteTO(result)+"  pid=="+byteTO(pid)+"====="+byteTO(mes1));
            //System.out.println("id:"+id+"r:"+response+"==r="+ result+"==pid="+mes2+"==id+r"+mes1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return result;
    }
    public byte[] H2( byte[] a, byte[] pid){
        try{
          // System.out.println("-----------------------------------"+byteTO(a)+"      " +byteTO(pid));
           // String comb= a+" "+pid;
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(a);
            md.update(pid);
            //byte[] mes1 = md.digest(comb.getBytes(StandardCharsets.UTF_8));
           //System.out.println("                    "+byteTO(md.digest()));
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public byte[]  H3(byte[] pid,int K,byte[] ra ){
        byte[] result;
        try {

            String input = pid.toString() + " " + K;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] mes1 = md.digest(input.getBytes(StandardCharsets.UTF_8));  //H1(ID,R)
            byte[] bytes=new byte[8];

            byte[] mes2 = ra;  //random
            byte[] newA=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            byte[] newB=new byte[mes1.length > mes2.length ? mes1.length : mes2.length];

            System.arraycopy(mes1,0,newA,0,mes1.length);
            System.arraycopy(mes2,0,newB,0,mes2.length);
            //System.out.println(mes2+"?");
            result = new byte[mes1.length > mes2.length ? mes1.length : mes2.length];
            for (int i = 0; i < (mes1.length > mes2.length ? mes1.length : mes2.length); i++) {
                result[i] = (byte) (newA[i] ^ newB[i]);
            }
            //
            //System.out.println("id:"+id+"r:"+response+"==r="+mes2+"==pid="+result+"==id+r"+mes1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return result;
    }
    public byte[]  H4(byte[] pid,int gid,byte[] k,byte[] random){
        try{
            MessageDigest digest=MessageDigest.getInstance("MD5");
           // String comb=pid.toString()+gid+k+random;
            digest.update(pid);
            digest.update((byte) gid);
            digest.update(k);
            digest.update(random);
            //byte[] hash=digest.digest(comb.getByts(StandardCharsets.UTF_8));
//            System.out.println(hash);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public byte[]  H5(byte[] ra,int gid){
        try{
            MessageDigest digest=MessageDigest.getInstance("MD5");
           // System.out.println( "ra :" +byteTO(ra)+"   gid :"+gid);
            //String comb= ra.toString()+gid;
            digest.update(ra);
            digest.update((byte) gid);
            //byte[] hash=digest.digest(comb.getBytes(StandardCharsets.UTF_8));
          // System.out.println(byteTO(digest.digest()));
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
