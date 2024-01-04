package Device;

import Hash.Hash;
import PhysicalFun.PsedoPUF;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class GroupLeaderDevice {
    private byte[] pid;
    private int id;
    private int gid;
    private String challenge;
    private String response;
    private String MAC;
    private String MAC2;
    private static List<MachineDevice> devices=new ArrayList<>();   //组长的成员列表
    private MAC verify;

    private PsedoPUF puf;
    private Hash hash=new Hash();
    private long random;

    public GroupLeaderDevice(int id, int gid, String challenge) {
        this.id = id;
        this.gid = gid;
        this.challenge = challenge;
        SecureRandom secureRandom=new SecureRandom();
        long random=secureRandom.nextLong();
        this.random=random;
        puf=new PsedoPUF();
        this.response=puf.generateRespon(challenge);
        this.pid=hash.H1(id,response,random);
    }

    public void addDevice(MachineDevice machineDevice){
        devices.add(machineDevice);
    }   //向组长中添加设备

    public void calculateMAC(){
        byte[] MAC=null;
        byte[] currentresult=null;
        for (MachineDevice m : devices) {
            if (MAC==null){
                MAC=m.getMAC().getBytes();
            }else {
                currentresult=m.getMAC().getBytes();
                for (int i = 0; i < MAC.length; i++) {
                    MAC[i]=(byte) (MAC[i]^currentresult[i]);
                }   //各位的异或计算
            }
        }
        this.MAC=byteTO(MAC);  //显示成十六进制
    }

    public void calculateMAC2(){
        byte[] MAC=null;
        for (MachineDevice m : devices) {
            byte[] currentresult;
            if (MAC==null){
                MAC=m.getMAC2().getBytes();
            }else {
                currentresult=m.getMAC2().getBytes();
                for (int i = 0; i < MAC.length; i++) {
                    MAC[i]=(byte) (MAC[i]^currentresult[i]);
                }
            }
        }
        this.MAC2=byteTO(MAC);
    }

    public static String byteTO(byte[] hash){   //将字节数组转换为十六进制表示的字符串
       // System.out.println(hash.length);
        StringBuffer heString=new StringBuffer(2* hash.length);  //创建一个 StringBuffer 对象，用于构建字符串
        for (byte b : hash) {
            //System.out.println(b);
            String hex = Integer.toHexString(0xff & b);   //将每个字节转换为十六进制字符串
            if (hex.length()==1){
                heString.append('0');  //如果十六进制字符串长度为 1，添加 '0' 补齐
            }
            heString.append(hex);  //将十六进制字符串添加到 StringBuffer 中
        }
        return  heString.toString();  //将 StringBuffer 转换为最终的字符串并返回
    }

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

    public String getMAC() {
        return MAC;
    }

    public void setMAC(String MAC) {
        this.MAC = MAC;
    }

    public  List<MachineDevice> getDevices() {
        return devices;
    }

    public  void setDevices(List<MachineDevice> devices) {
        GroupLeaderDevice.devices = devices;
    }

    public String getMAC2() {
        return MAC2;
    }

    public void setMAC2(String MAC2) {
        this.MAC2 = MAC2;
    }

    @Override
    public String toString() {
        return "GroupLeaderDevice{" +
                "id=" + id +
                ", gid=" + gid +
                '}';
    }
}
