package AMF;

import Device.MAC;
import Device.MachineDevice;
import Hash.Hash;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AMF {
    private int IDamf;
    private Long ra;
    private byte[] ra2=new byte[16];
    private byte[] K;
    private List<byte[]> K_list=new ArrayList<>();
    private byte[] V;
    private List<byte[]> V_list=new ArrayList<>();
    private byte[] SK;
    private List<byte[]> SK_list=new ArrayList<>();
    private byte[] GK;
    private List<byte[]> GK_list=new ArrayList<>();
    private String MACa;
    private List<String> MACa_list=new ArrayList<>();
    private MAC mac=new MAC();
    private static Hash hash=new Hash();
    private String MAC2;

    public AMF(int IDamf) {
        this.IDamf = IDamf;
        SecureRandom secureRandom=new SecureRandom();
        long ra=secureRandom.nextLong();
        byte[] bytes=new byte[8];
        for (int i = 7; i >=0 ; i--) {
            bytes[i]=(byte) (ra & 0xFF);
            ra>>=8;
        }
        byte[] newA=new byte[16];
        System.arraycopy(bytes,0,newA,0,bytes.length);  //扩容到128
        this.ra2=newA;
    }


    public byte[] calculateK(byte[] ra2,byte[] pid){
//        System.out.println("        "+byteTO(ra2)+"    "+byteTO(pid));
        K_list.add(hash.H2(ra2,pid));
        return hash.H2(ra2,pid);
    }
    public byte[] calculateSK(byte[] pid,int gid,byte[] k,byte[] random){
        SK_list.add(hash.H4( pid, gid,k, random));
        return hash.H4( pid, gid, k,random);
    }
    public byte[] calculateV(byte[] pid,int IDamf,byte[] ra2){
        V_list.add(hash.H3(pid, IDamf,ra2));
        return hash.H3(pid, IDamf,ra2);
    }
    public byte[] calculateGK(byte[] ra2,int gid){
        GK_list.add( hash.H5(ra2,gid));
        return hash.H5(ra2,gid);
    }
    public String calculateMACa(byte[] pid, int gid, int IDamf, byte[] V ,byte[] K, byte[] GK){
     MACa_list.add(mac.generateMACa(pid,gid,IDamf,V,K,GK));
     return mac.generateMACa(pid,gid,IDamf,V,K,GK);
    }

    public void receiveMessageMAC2(String mac2,List<MachineDevice> devices){
        calculateMAC2(devices);
        if (Objects.equals(mac2,MAC2)){
            System.out.println("验证成功");
        }else{
            System.out.println("验证失败");
        }

    }

    public void calculateMAC2(List<MachineDevice> devices){
        byte[] MAC=null;
        for (MachineDevice m : devices) {
            byte[] currentresult;
            if (MAC==null){
                MAC=m.getMAC2().getBytes();
            }else {
                currentresult=m.getMAC2().getBytes();
                for (int i = 0; i < MAC.length; i++) {
                    MAC[i]=(byte) (MAC[i]^currentresult[i]);
                }   //各位的异或计算
            }
        }
        this.MAC2=byteTO(MAC);  //显示成十六进制
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

    public List<String> getMACa_list() {
        return MACa_list;
    }

    public void setMACa_list(List<String> MACa_list) {
        this.MACa_list = MACa_list;
    }

    public int getIDamf() {
        return IDamf;
    }

    public void setIDamf(int IDamf) {
        this.IDamf = IDamf;
    }

    public Long getRa() {
        return ra;
    }

    public void setRa(Long ra) {
        this.ra = ra;
    }

    public byte[] getRa2() {
        return ra2;
    }

    public void setRa2(byte[] ra2) {
        this.ra2 = ra2;
    }

    public byte[] getK() {
        return K;
    }

    public void setK(byte[] k) {
        K = k;
    }

    public List<byte[]> getK_list() {
        return K_list;
    }

    public void setK_list(List<byte[]> k_list) {
        K_list = k_list;
    }

    public byte[] getV() {
        return V;
    }

    public void setV(byte[] v) {
        V = v;
    }

    public List<byte[]> getV_list() {
        return V_list;
    }

    public void setV_list(List<byte[]> v_list) {
        V_list = v_list;
    }

    public byte[] getSK() {
        return SK;
    }

    public void setSK(byte[] SK) {
        this.SK = SK;
    }

    public List<byte[]> getSK_list() {
        return SK_list;
    }

    public void setSK_list(List<byte[]> SK_list) {
        this.SK_list = SK_list;
    }

    public byte[] getGK() {
        return GK;
    }

    public void setGK(byte[] GK) {
        this.GK = GK;
    }

    public List<byte[]> getGK_list() {
        return GK_list;
    }

    public void setGK_list(List<byte[]> GK_list) {
        this.GK_list = GK_list;
    }

    public String getMACa() {
        return MACa;
    }

    public void setMACa(String MACa) {
        this.MACa = MACa;
    }

    public MAC getMac() {
        return mac;
    }

    public void setMac(MAC mac) {
        this.mac = mac;
    }

}
