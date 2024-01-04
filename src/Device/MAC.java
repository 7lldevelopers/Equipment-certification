package Device;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class MAC {

    public String generateMAC( byte[] pid,int gid,int IDamf,long random){
        try {
            String input = pid + " " + gid+" "+IDamf+" "+random;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] mac1 = md.digest(input.getBytes());
            return byteTO(mac1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateMACa(byte[] pid, int gid, int IDamf,  byte[] V ,byte[] K, byte[] GK){ //MACa

        try {
            MessageDigest digest=MessageDigest.getInstance("MD5");
            // System.out.println( "ra :" +byteTO(ra)+"   gid :"+gid);
            digest.update(pid);
            digest.update((byte) gid);
            digest.update((byte) IDamf);
            digest.update(V);
            digest.update(K);
            digest.update(GK);
            //byte[] hash=digest.digest(comb.getBytes(StandardCharsets.UTF_8));
            // System.out.println(byteTO(digest.digest()));
            return byteTO(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateMAC2(byte[] pid, int gid, int IDamf,  byte[] SK ,byte[] K, byte[] GK){

        try {
            MessageDigest digest=MessageDigest.getInstance("MD5");
            // System.out.println( "ra :" +byteTO(ra)+"   gid :"+gid);
            digest.update(pid);
            digest.update((byte) gid);
            digest.update((byte) IDamf);
            digest.update(SK);
            digest.update(K);
            digest.update(GK);
            //byte[] hash=digest.digest(comb.getBytes(StandardCharsets.UTF_8));
            // System.out.println(byteTO(digest.digest()));
            return byteTO(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateMACi1(int bid,byte[] pid,  int gid, byte[] K, byte[] GK){

        try {
            MessageDigest digest=MessageDigest.getInstance("MD5");
            // System.out.println( "ra :" +byteTO(ra)+"   gid :"+gid);
            digest.update((byte) bid);
            digest.update(pid);
            digest.update((byte) gid);
            digest.update(K);
            digest.update(GK);
            //byte[] hash=digest.digest(comb.getBytes(StandardCharsets.UTF_8));
            // System.out.println(byteTO(digest.digest()));
            return byteTO(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateMACg1(int bid,byte[] pid,  int gid, int IDamf,byte[] K){
        try {
            MessageDigest digest=MessageDigest.getInstance("MD5");
            digest.update((byte) bid);
            digest.update(pid);
            digest.update((byte) gid);
            digest.update((byte) IDamf);
            digest.update(K);
            return byteTO(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String byteTO(byte[] hash){
        StringBuffer heString=new StringBuffer(2* hash.length);
        for (byte b :
                hash) {
            //System.out.println(b);
            String hex = Integer.toHexString(0xff & b);
            if (hex.length()==1){
                heString.append('0');
            }
            heString.append(hex);
        }
        return  heString.toString();
    }


}
