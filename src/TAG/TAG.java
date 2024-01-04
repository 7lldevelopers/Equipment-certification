package TAG;

import Device.GroupLeaderDevice;
import Device.MachineDevice;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class TAG {

    private int TAG;

    private String plaintext;
    private  List<GroupLeaderDevice> devices=new ArrayList<>();

    public TAG(List<GroupLeaderDevice> devices) {
        this.devices = devices;
    }

    public void  tag(int tag,  String plaintext){
        this.TAG=tag;

        this.plaintext=plaintext;

        for (GroupLeaderDevice M :
                devices) {
            for (MachineDevice m:
                    M.getDevices()) {
                //依次将信息广播给所有设备
                try {
                    String a=m.Tag_send();
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
        }

    }

    public static void main(String[] args) {

        List<MachineDevice> devices = new ArrayList<>();  //设备容器
        int i = 0;
        while (devices.size() < 10) {
            devices.add(new MachineDevice(i++, 1, UUID.randomUUID().toString(), 1));  //随机生成挑战
        }
        for (MachineDevice m :
                devices) {
            System.out.println(m.toString());  //输出设备信息
        }
        //设置组长设备
        System.out.println("-----设置组长设备----");
        GroupLeaderDevice GLDevice = new GroupLeaderDevice(10, 1, "randomUUID");
        System.out.println(GLDevice.toString());
        for (MachineDevice m :
                devices) {
            GLDevice.addDevice(m);
        }
        List<GroupLeaderDevice> a=new ArrayList<>();
        a.add(GLDevice);
        TAG tag=new TAG(a);
        tag.tag(1,"asdasds");


    }

}
