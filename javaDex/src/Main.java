import java.util.SplittableRandom;

public class Main {
    public static DexType dexType = new DexType();

    public static void main(String[] args) {
        //dex位置
        String path = "/home/wmh/Desktop/classes.dex";

        //read dex to byte[]
        byte[] dexFileByte = DexUtil.readFile(path);

        //处理头部
        ReadDex readDex =new ReadDex();
        readDex.readHeader(dexFileByte);

        Resolve resolve = new Resolve();
        resolve.resolveHeader();

        //处理StringList
        int stringIdsSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.stringIdsSize));
        int stringIdsOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.stringIdsOff));
        readDex.readDexStringId(dexFileByte,stringIdsSize,stringIdsOff);
        resolve.resoveStingList(dexFileByte);


        //处理TypeList
        int typeIdsSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.typeIdsSize));
        int typeIdsOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.typeIdsOff));
        readDex.readDexTypeId(dexFileByte,typeIdsSize,typeIdsOff);
        resolve.resoveTypeList();

        //处理proroList
        int proroIdsSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.protoIdsSize));
        int proroIdsOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.protoIdsOff));
        readDex.readDexProtoId(dexFileByte,proroIdsSize,proroIdsOff);
        resolve.resoveProtoList(dexFileByte,readDex);

        //处理field
        int fieldSiza = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.fieldIdsSize));
        int fieldOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.fieldIdsOff));
        readDex.readDexFieldId(dexFileByte,fieldSiza,fieldOff);
        resolve.resoveFieldList();

        //处理methodList
        int methodIdsSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.methodIdsSize));
        int methodIdsOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.methodIdsOff));
        readDex.readDexMethodId(dexFileByte,methodIdsSize,methodIdsOff);
        resolve.resoveMethodList();

        //处理classDefList
        int classDefsSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.classDefsSize));
        int classDefsOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.classDefsOff));
        readDex.readClassDefId(dexFileByte,classDefsSize,classDefsOff);
        resolve.resoveClassDefList(dexFileByte,readDex);

        //处理MapList
        int mapListOff = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexHeader.mapOff));
        readDex.readMapList(dexFileByte,mapListOff);
        resolve.resolveMapList();



    }
}
