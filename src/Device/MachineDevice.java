package Device;

import Hash.Hash;
import PhysicalFun.PsedoPUF;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLOutput;
import java.util.*;

public class MachineDevice {
    private byte[] pid;
    private int id;
    private int gid;
    private int IDamf;
    private String challenge;
    private String response;
    private String MAC;
    private MAC verify;  //计算MAC值
    private PsedoPUF puf;  //计算响应response
    private Hash hash;
    private long random;  //初始随机数64
    private byte[] random2;  //扩容后的随机数128
    //******************设备认证网络层数据*************************
    private byte[] ra2;//网络层随机数（扩容后的）
    private byte[] K;
    private byte[] V;
    private byte[] SK;
    private byte[] GK;

    private String MACai;

    private String MAC2;
    //***************************广播****************************
    private String cipherText;

    private String decryptedText;

    private String key;
    private String maci1;

    private int bid;

    public MachineDevice(int id, int gid, String challenge, int IDamf) {
        this.id = id;
        this.gid = gid;
        this.IDamf=IDamf;
        this.challenge = challenge;
        puf=new PsedoPUF();
        verify=new MAC();
        hash=new Hash();
        SecureRandom secureRandom=new SecureRandom();
        long random=secureRandom.nextLong();
        this.random=random;
        this.response=puf.generateRespon(challenge);

        Random A=new Random();
        this.bid=A.nextInt(100);

        byte[] bytes=new byte[8];  //创建一个长度为8的字节数组（byte类型为1字节）
        for (int i = 7; i >=0 ; i--) {
            bytes[i]=(byte) (random & 0xFF);
            random>>=8;
        }   //用于将random的每个字节存储到bytes数组中，实现将其拆分为字节数组的目的

        byte[] newA=new byte[16];
        System.arraycopy(bytes,0,newA,0,bytes.length);  //扩容到128
        random2=newA;
        this.pid=hash.H1(id,response,random2);
        //System.out.println(random2);
        this.MAC=verify.generateMAC(pid,gid,IDamf,random);
    }

    public void calculate(){
        this.MAC=verify.generateMAC(pid,gid,IDamf,random);
    }

    public void AMF_Certification(byte[] V, String MACa){// 网络层传输的数据 V 和 MACa

        this.ra2=hash.H3(this.pid, this.IDamf,V);
        // System.out.println(" V:"+byteTO(V)+"ra2 "+byteTO(this.ra2));
        //System.out.println(byteTO(this.ra2)+"      " +byteTO(this.pid));
        this.K=hash.H2(this.ra2,this.pid);
        //System.out.println("K: "+byteTO(K));
        this.SK=hash.H4(this.pid,this.gid,this.K,this.random2);
        this.GK=hash.H5(this.ra2,this.gid);
        //System.out.println("GK: "+byteTO(GK));
        this.MACai=verify.generateMACa(this.pid,this.gid,this.IDamf,V,this.K,this.GK);
        if (Objects.equals(this.MACai,MACa)){
            System.out.println("设备"+this.id+"验证MACa："+"true");
        }
        this.MAC2=verify.generateMAC2(this.pid,this.gid,this.IDamf,this.SK,this.K,this.GK);
        //this.maci1=verify.generateMACi1()

    }

    public void cipher_gk() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        System.out.println();
        this.maci1=verify.generateMACi1(bid, pid, gid, K, GK);
        System.out.println("加密前 :"+byteTO(pid)+"  "+gid+" "+maci1);  //明文
        String text=byteTO(pid)+"-"+gid+"-"+maci1;

        //System.out.println("ra2="+byteTO(ra2)+"  pid="+byteTO(pid));
        //System.out.println("K="+byteTO(K));
        //System.out.println(text);
        this.key=byteTO(GK);
        //System.out.println(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  //AES算法、ECB模式（ECB将text扩容成16的倍数）和PKCS5Padding填充方式
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  //采用ENCRYPT_MODE方法用密钥secretKey对文本进行加密
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());  //密文   对‘text’进行加密
        cipherText=Base64.getEncoder().encodeToString(encryptedBytes);   //将加密后的字节数组使用 Base64 编码转换为字符串
        System.out.println("加密后："+cipherText);
    }

    public void decrypt_gk(int bid1,String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //System.out.println(CIP);
        this.key=byteTO(GK);
        //System.out.println(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);   //采用DECRYPT_MODE方法用密钥secretKey对文本进行加密

        byte[] encryptedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        decryptedText=new String(decryptedBytes);
        System.out.println("解密后："+decryptedText);
        //解密 string 到3个数据 pid-gid-maci1
        String[] parts = decryptedText.split("-");
        System.out.println("拆分："+parts[0]+"   "+parts[1]+"   "+parts[2]);

        //System.out.println("ra2="+byteTO(ra2)+"   pid="+parts[0]);  //K=H(ra,PID)
        byte[] c_K=hash.H2(this.ra2,parts[0].getBytes());
        System.out.println("c_k= "+byteTO(c_K));

        if (gid==Integer.parseInt(parts[1])){
            System.out.println("GID验证成功");
        }else {
            System.out.println("GID验证成功");
        }
        //System.out.println("bid1="+bid1+"pid="+parts[0]+"gid="+parts[1]+"k="+c_K+"Gk="+GK);
        String result=verify.generateMACi1(bid1, parts[0].getBytes(),  Integer.parseInt(parts[1]),  c_K,  GK);
        if (Objects.equals(result,parts[2])){
            System.out.println("MACi1验证成功");
        }else {
            System.out.println("MACi1验证失败");
        }

    }

    public String Tag_send() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        cipher_gk();
        return this.cipherText;
    }

    public void Tag_accept(int bid,String cipher) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        decrypt_gk(bid,cipher);

    }

    public String getMACa() {
        return MACai;
    }

    public void setMACa(String MACa) {
        this.MACai = MACa;
    }

    public String getMAC2() { return MAC2; }

    public void setMAC2(String MAC2) {
        this.MAC2 = MAC2;
    }    //后期若是修改MAC2值，直接调用setMAC2

    public byte[] getPid() {
        return pid;
    }

    public void setPid(byte[] pid) {
        this.pid = pid;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getGid() {
        return gid;
    }

    public void setGid(int gid) {
        this.gid = gid;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public int getIDamf() {
        return IDamf;
    }

    public void setIDamf(int IDamf) {
        this.IDamf = IDamf;
    }

    public String getR() {
        return response;
    }

    public void setR(String R) {
        this.response = R;
    }

    public String getMAC() {
        return MAC;
    }

    public void setMAC(String MAC) { this.MAC = MAC; }

    public int getBid() {
        return bid;
    }

    public void setBid(int bid) {
        this.bid = bid;
    }

    @Override
    public String toString() {
        return "MachineDevice{" +
                "id=" + id +
                ", gid=" + gid +
                ", pid='" + byteTO(pid) + '\'' +
                ", random='" + random + '\'' +
                ", challenge='" + challenge + '\'' +
                ", response='" + response + '\'' +
                ", MAC='" + MAC + '\'' +
                '}';
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
