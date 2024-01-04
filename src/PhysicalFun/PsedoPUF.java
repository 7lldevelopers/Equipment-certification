package PhysicalFun;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
/*
* 挑战 c
* 响应 r
* */
public class PsedoPUF implements PsudoPUF{

    private int random=1;
    // 实现接口中的方法
    @Override
    public String generateRespon(String challenge){  //模拟PUF
        try{
            MessageDigest digest=MessageDigest.getInstance("SHA-256");  // 创建 SHA-256 摘要对象
            String comb=challenge+random;   // 将挑战值和随机数组合成一个字符串
            byte[] hash=digest.digest(comb.getBytes());   // 对组合字符串计算 SHA-256 摘要
//            System.out.println(hash);
            return byteTO(hash);   // 返回摘要的十六进制表示
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public static String byteTO(byte[] hash){
        StringBuffer heString=new StringBuffer(2* hash.length);
        for (byte b : hash) {
            //System.out.println(b);
            String hex = Integer.toHexString(0xff & b);
            if (hex.length()==1){
                heString.append('0');
            }
            heString.append(hex);
        }
        return  heString.toString();
    }

    //test
    public static void main(String[] args) {
        PsedoPUF a=new PsedoPUF();
        String c="challenge";
        String r=a.generateRespon(c);
        System.out.println(r);
    }
}
//r: 97b38a5a5fa255374d3f0afbb2bc341003ec1d9d5ae470d06654d7f403f21c16 c: challenge
//r: 739a367a6f97c4a33d997b0f5be60461cfd7453bea4941efdf18f258318d6a3a c: challenge1
//r: 97b38a5a5fa255374d3f0afbb2bc341003ec1d9d5ae470d06654d7f403f21c16 c: challenge