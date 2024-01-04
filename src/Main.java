import AMF.AMF;
import Device.GroupLeaderDevice;
import Device.MachineDevice;
import Server.CertificationServer;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
//0r==[B@6ff3c5b5  pid==[B@3764951d=====[B@4b1210ee
//                 0pid==[B@6ff3c5b5  pid==[B@3764951d=====[B@4b1210ee
public class Main {
    public static void main(String[] args) {
        //设备数量
        int device = 10;
        //设备注册
        System.setOut(new PrintStream(System.out,true, StandardCharsets.UTF_8));
        System.out.println("------设备注册------");
        List<MachineDevice> devices = new ArrayList<>();  //设备容器

        int i = 0;
        while (devices.size() < device-1) {
            devices.add(new MachineDevice(i++, 1, UUID.randomUUID().toString(), 1));  //随机生成挑战
        }

        for (MachineDevice m : devices) {
            System.out.println(m.toString());  //输出设备信息
        }

        System.out.println("-----设置组长设备----");
        GroupLeaderDevice GLDevice = new GroupLeaderDevice(9, 1, "randomUUID");
        System.out.println(GLDevice.toString());

        for (MachineDevice m : devices) {
            GLDevice.addDevice(m);
        }

        GLDevice.calculateMAC();
        System.out.println("组长计算MAC1值：" + GLDevice.getMAC());

        System.out.println("-----AMF中继转发-------");
        AMF amf = new AMF(1);

        System.out.println("-----AUSF验证---------");
        CertificationServer certificationServer = new CertificationServer();
        certificationServer.addGroupLeaderDevices(GLDevice);
        certificationServer.receiveMessage(GLDevice.getPid(), 1, GLDevice.getMAC());

        System.out.println("-----AMF接收数据并计算---------");
        byte[] ra = amf.getRa2();
        System.out.println("ra=" + byteTO(ra));

        for (MachineDevice e : GLDevice.getDevices()) {

            byte[] V = amf.calculateV(e.getPid(), e.getIDamf(), ra);
            System.out.println("设备"+ e.getId() + " V:" + byteTO(V));

            byte[] k = amf.calculateK(ra, e.getPid());
            System.out.println(" K:" + byteTO(k));

            byte[] sk = amf.calculateSK(e.getPid(), e.getGid(), V, ra);
            System.out.println(" SK:" + byteTO(sk));

            byte gk[] = amf.calculateGK(ra, e.getGid());
            System.out.println(" GK:" + byteTO(gk));

            String maca = amf.calculateMACa(e.getPid(), e.getGid(), e.getIDamf(), V, k, gk);
            System.out.println(" MACa:" + maca);
        }

        System.out.println("-----设备认证网络---------");
        for (int j = 0; j < devices.size(); j++) {
            devices.get(j).AMF_Certification(amf.getV_list().get(j), amf.getMACa_list().get(j));
            System.out.println("MAC2"+j+":"+devices.get(j).getMAC2());
            //加上输出MAC2i
        }

        System.out.println("-----GL计算MAC2---------");
        GLDevice.calculateMAC2();
        System.out.println("组长计算MAC2值：" + GLDevice.getMAC2());

        System.out.println("-----AMF认证---------");
        amf.receiveMessageMAC2(GLDevice.getMAC2(),GLDevice.getDevices());

        System.out.println("-------广播-----------");
        try {
            for (int k = 0; k < GLDevice.getDevices().size(); k++) {
                for (int j = 0; j <  GLDevice.getDevices().size(); j++) {
                    if (j!=k)
                        GLDevice.getDevices().get(j).Tag_accept(GLDevice.getDevices().get(k).getBid(),GLDevice.getDevices().get(k).Tag_send());
                }
            }

        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public static String byteTO(byte[] hash) {
        StringBuffer heString = new StringBuffer(2 * hash.length);
        for (byte b :
                hash) {
            //System.out.println(b);
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                heString.append('0');
            }
            heString.append(hex);
        }
        return heString.toString();
    }}
