package Server;

import Device.GroupLeaderDevice;
import Device.MachineDevice;
import Hash.Hash;

import java.math.BigInteger;
import java.sql.SQLOutput;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;

public class CertificationServer {
    private static List<GroupLeaderDevice> groupLeaderDevices=new ArrayList<>(); ;
    private long random;
    public void receiveMessage( byte[] pid,int IDamf,String MAC){
        for (GroupLeaderDevice g : groupLeaderDevices) {
            if (Objects.equals(g.getPid(),pid)){
                System.out.println("AUSF验证组长PID:true");
                calculateRandom(g);
                for (MachineDevice m:g.getDevices()) {
                    m.calculate();
                }
                String ever=g.getMAC();
                if (Objects.equals(MAC,ever)){
                    System.out.println("AUSF验证MAC:true");
                }else {
                    System.out.println("AUSF验证MAC:false");
                }
            }else {
                System.out.println("AUSF验证组长PID:false");
            }
        }

    }
    public static void calculateRandom(GroupLeaderDevice g){
        Hash hash=new Hash();
        for (MachineDevice m : g.getDevices()) {
            byte[] a=hash.H1(m.getId(),m.getR(),m.getPid());

        }
    }
    public List<GroupLeaderDevice> getGroupLeaderDevices() {
        return groupLeaderDevices;
    }
    public void  addGroupLeaderDevices(GroupLeaderDevice a){
        groupLeaderDevices.add(a);
    }
    public long getRandom() {
        return random;
    }

    public void setRandom(long random) {
        this.random = random;
    }
}
