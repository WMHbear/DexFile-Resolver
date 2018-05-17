import java.util.ArrayList;

public class ReadDex {


    //读取header
    public void readHeader(byte[] header_addr){
        Main.dexType.dexHeader.magic = DexUtil.copyBytes(header_addr,0,8);
        Main.dexType.dexHeader.checksum = DexUtil.copyBytes(header_addr,8,4);
        Main.dexType.dexHeader.signature = DexUtil.copyBytes(header_addr,12,20);
        Main.dexType.dexHeader.fileSize = DexUtil.copyBytes(header_addr,32,4);
        Main.dexType.dexHeader.headerSize = DexUtil.copyBytes(header_addr,36,4);
        Main.dexType.dexHeader.endianTag = DexUtil.copyBytes(header_addr,40,4);
        Main.dexType.dexHeader.linkSize = DexUtil.copyBytes(header_addr,44,4);
        Main.dexType.dexHeader.linkOff = DexUtil.copyBytes(header_addr,48,4);
        Main.dexType.dexHeader.mapOff = DexUtil.copyBytes(header_addr,52,4);
        Main.dexType.dexHeader.stringIdsSize = DexUtil.copyBytes(header_addr,56,4);
        Main.dexType.dexHeader.stringIdsOff = DexUtil.copyBytes(header_addr,60,4);
        Main.dexType.dexHeader.typeIdsSize = DexUtil.copyBytes(header_addr,64,4);
        Main.dexType.dexHeader.typeIdsOff = DexUtil.copyBytes(header_addr,68,4);
        Main.dexType.dexHeader.protoIdsSize = DexUtil.copyBytes(header_addr,72,4);
        Main.dexType.dexHeader.protoIdsOff = DexUtil.copyBytes(header_addr,76,4);
        Main.dexType.dexHeader.fieldIdsSize = DexUtil.copyBytes(header_addr,80,4);
        Main.dexType.dexHeader.fieldIdsOff = DexUtil.copyBytes(header_addr,84,4);
        Main.dexType.dexHeader.methodIdsSize = DexUtil.copyBytes(header_addr,88,4);
        Main.dexType.dexHeader.methodIdsOff = DexUtil.copyBytes(header_addr,92,4);
        Main.dexType.dexHeader.classDefsSize = DexUtil.copyBytes(header_addr,96,4);
        Main.dexType.dexHeader.classDefsOff = DexUtil.copyBytes(header_addr,100,4);
        Main.dexType.dexHeader.dataSize = DexUtil.copyBytes(header_addr,104,4);
        Main.dexType.dexHeader.dataOff = DexUtil.copyBytes(header_addr,108,4);
    }

    //处理stringlist
    public DexType.DexStringId readDexStingDataOff(byte[] data_byte){
        DexType.DexStringId dexStringId= Main.dexType.new DexStringId();
        dexStringId.stringDataOff = data_byte;
        return dexStringId;
    }

    public void readDexStringId(byte[] base_addr,int string_number,int string_off){
        for(int i =0;i<string_number;i++){
            Main.dexType.dexStringId.add(readDexStingDataOff(DexUtil.copyBytes(base_addr,string_off + (i*4),4)));
        }
    }

    //处理typelist
    public DexType.DexTypeId readDexDescriptorIdx(byte[] data_byte){
        DexType.DexTypeId dexTypeId= Main.dexType.new DexTypeId();
        dexTypeId.descriptorIdx = data_byte;
        return dexTypeId;
    }

    public void readDexTypeId(byte[] base_addr,int type_number,int type_off){
        for(int i =0;i<type_number;i++){
            Main.dexType.dexTypeId.add(readDexDescriptorIdx(DexUtil.copyBytes(base_addr,type_off + (i*4),4)));
        }
    }

    //处理protoList
    public DexType.DexProtoId readDexProtoIdx(byte[] data_byte){
        DexType.DexProtoId dexProtoId =Main.dexType.new DexProtoId();
        dexProtoId.shortyIdx = DexUtil.copyBytes(data_byte,0,4);
        dexProtoId.returnTypeIdx = DexUtil.copyBytes(data_byte,4,4);
        dexProtoId.parametersOff = DexUtil.copyBytes(data_byte,8,4);
        return dexProtoId;
    }

    public void readDexProtoId(byte[] base_addr,int proto_number,int proto_off){
        for(int i=0;i<proto_number;i++){
            Main.dexType.dexProtoId.add(readDexProtoIdx(DexUtil.copyBytes(base_addr,proto_off + (i*12),12)));
        }
    }

    public DexType.DexTypeItem readDexItem(byte[] data_byte){
        DexType.DexTypeItem dexTypeItem = Main.dexType.new DexTypeItem();
        dexTypeItem.typeIdx = DexUtil.copyBytes(data_byte,0 ,2);
        return dexTypeItem;
    }


    public DexType.DexTypeList readDexTypeLists (byte[] data_byte,int itemSize){
        DexType.DexTypeList dexTypeList = Main.dexType.new DexTypeList();
        dexTypeList.size = DexUtil.copyBytes(data_byte,0 ,4);
        for(int j=0;j<itemSize;j++){
            dexTypeList.list.add(readDexItem(DexUtil.copyBytes(data_byte,4 + (j*2) ,2)));
        }
        return dexTypeList;
    }

    public void readDexTypeList(byte[] base_addr,int param_off){
        int itemSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(DexUtil.copyBytes(base_addr,param_off ,4)));
        Main.dexType.dexTypeLists.add(readDexTypeLists(DexUtil.copyBytes(base_addr,param_off,itemSize *2 +4),itemSize));
    }

    //处理fieldList
    public DexType.DexFieldId readDexFiledIds(byte[] data_byte){
        DexType.DexFieldId dexFieldId = Main.dexType.new DexFieldId();
        dexFieldId.classIdx = DexUtil.copyBytes(data_byte,0 ,2);
        dexFieldId.typeIdx = DexUtil.copyBytes(data_byte,2 ,2);
        dexFieldId.nameIdx = DexUtil.copyBytes(data_byte,4 ,4);
        return dexFieldId;
    }

    public void readDexFieldId(byte[] base_addr,int field_number,int field_off){
        for(int i =0;i<field_number;i++){
            Main.dexType.dexFieldId.add(readDexFiledIds(DexUtil.copyBytes(base_addr,field_off + (i*8),8)));
        }
    }

    //处理methodList
    public DexType.DexMethodId readDexMethodIds(byte[] data_byte){
        DexType.DexMethodId dexMethodId = Main.dexType.new DexMethodId();
        dexMethodId.classIdx = DexUtil.copyBytes(data_byte,0 ,2);
        dexMethodId.protoIdx = DexUtil.copyBytes(data_byte,2 ,2);
        dexMethodId.nameIdx = DexUtil.copyBytes(data_byte,4 ,4);
        return dexMethodId;
    }

    public void readDexMethodId(byte[] base_addr,int method_number,int method_off){
        for(int i =0;i<method_number;i++){
            Main.dexType.dexMethodId.add(readDexMethodIds(DexUtil.copyBytes(base_addr,method_off + (i*8),8)));
        }
    }

    //处理classDefList
    public DexType.DexClassDef readDexClassDef(byte[] data_byte){
        DexType.DexClassDef dexClassDef = Main.dexType.new DexClassDef();
        dexClassDef.classIdx = DexUtil.copyBytes(data_byte,0 ,4);
        dexClassDef.accessFlags = DexUtil.copyBytes(data_byte,4 ,4);
        dexClassDef.superclassIdx = DexUtil.copyBytes(data_byte,8 ,4);
        dexClassDef.interfacesOff = DexUtil.copyBytes(data_byte,12 ,4);
        dexClassDef.sourceFileIdx = DexUtil.copyBytes(data_byte,16 ,4);
        dexClassDef.annotationsOff = DexUtil.copyBytes(data_byte,20 ,4);
        dexClassDef.classDataOff = DexUtil.copyBytes(data_byte,24 ,4);
        dexClassDef.staticValuesOff = DexUtil.copyBytes(data_byte,28 ,4);
        return dexClassDef;

    }

    public void readClassDefId(byte[] base_addr,int classdef_number,int classdef_off){
        for(int i =0;i < classdef_number;i++){
            Main.dexType.dexClassDefs.add(readDexClassDef(DexUtil.copyBytes(base_addr,classdef_off + (i*32),32)));
        }
    }

    //处理classDefData
    public void readClassDefData(byte[] base_addr,int defData_off){
        int allSize = 0;

        //总体DexClassData结构
        DexType.DexClassData dexClassData = Main.dexType.new DexClassData();

        //先读取header
        int staticUlebSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off ,5));
        int instanceUlebSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off + staticUlebSize,5));
        int dirUlebSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off + staticUlebSize + instanceUlebSize,5));
        int virUlebSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off + staticUlebSize + instanceUlebSize + dirUlebSize,5));

        allSize =staticUlebSize+instanceUlebSize+dirUlebSize+virUlebSize;

        DexType.DexClassDataHeader defDataHeader = Main.dexType.new DexClassDataHeader();
        defDataHeader.staticFieldsSize = DexUtil.copyBytes(base_addr,defData_off ,staticUlebSize);
        defDataHeader.instanceFieldsSize = DexUtil.copyBytes(base_addr,defData_off + staticUlebSize , instanceUlebSize);
        defDataHeader.directMethodsSize = DexUtil.copyBytes(base_addr,defData_off + staticUlebSize + instanceUlebSize ,dirUlebSize);
        defDataHeader.virtualMethodsSize = DexUtil.copyBytes(base_addr,defData_off + staticUlebSize + instanceUlebSize +dirUlebSize ,virUlebSize);
        dexClassData.header.add(defDataHeader);

        //读取静态字段
        int staticFilednum = DexUtil.decodeUleb128(defDataHeader.staticFieldsSize);
        DexType.DexField staField = Main.dexType.new DexField();
        for(int i =0;i< staticFilednum;i++){
            int fieldIdSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize ,5));
            int acceflagSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + fieldIdSize,5));
            staField.fieldIdx = DexUtil.copyBytes(base_addr,defData_off +allSize ,fieldIdSize);
            staField.accessFlags =  DexUtil.copyBytes(base_addr,defData_off +allSize + fieldIdSize ,acceflagSize);
            dexClassData.staticFields.add(staField);
            allSize = allSize +fieldIdSize +acceflagSize;
        }

        //读取实例字段
        int instanceFilednum = DexUtil.decodeUleb128(defDataHeader.instanceFieldsSize);
        DexType.DexField instField = Main.dexType.new DexField();
        for(int j =0;j< instanceFilednum;j++){
            int fieldIdSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize ,5));
            int acceflagSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + fieldIdSize,5));
            instField.fieldIdx = DexUtil.copyBytes(base_addr,defData_off +allSize ,fieldIdSize);
            instField.accessFlags =  DexUtil.copyBytes(base_addr,defData_off +allSize + fieldIdSize ,acceflagSize);
            dexClassData.instanceFields.add(instField);
            allSize = allSize +fieldIdSize +acceflagSize;
        }

        //读取直接方法
        int dieMethodNum = DexUtil.decodeUleb128(defDataHeader.directMethodsSize);
        DexType.DexMethod dirMethod = Main.dexType.new DexMethod();
        for(int j =0;j< dieMethodNum;j++){
            int methodIdSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize ,5));
            int acceflagSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize,5));
            int codeOff = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize + acceflagSize,5));
            dirMethod.methodIdx = DexUtil.copyBytes(base_addr,defData_off +allSize ,methodIdSize);
            dirMethod.accessFlags =  DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize , acceflagSize);
            dirMethod.codeOff =  DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize + acceflagSize, codeOff);
            dexClassData.directMethods.add(dirMethod);
            allSize = allSize +methodIdSize +acceflagSize +codeOff ;
        }

        //读取虚方法
        int virMethodNum = DexUtil.decodeUleb128(defDataHeader.directMethodsSize);
        DexType.DexMethod virMethod = Main.dexType.new DexMethod();
        for(int z =0;z< virMethodNum;z++){
            int methodIdSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize ,5));
            int acceflagSize = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize,5));
            int codeOff = DexUtil.readULeb128(DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize + acceflagSize,5));
            virMethod.methodIdx = DexUtil.copyBytes(base_addr,defData_off +allSize ,methodIdSize);
            virMethod.accessFlags =  DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize , acceflagSize);
            virMethod.codeOff =  DexUtil.copyBytes(base_addr,defData_off +allSize + methodIdSize + acceflagSize, codeOff);
            dexClassData.virtualMethods.add(virMethod);
            allSize = allSize +methodIdSize +acceflagSize +codeOff ;
        }

        Main.dexType.dexClassData.add(dexClassData);

    }

    //处理mapList
    public DexType.DexMapItem readDexMapItem(byte[] data_byte){
        DexType.DexMapItem dexMapItem = Main.dexType.new DexMapItem();
        dexMapItem.type = DexUtil.copyBytes(data_byte,0 , 2);
        dexMapItem.unused = DexUtil.copyBytes(data_byte,2 , 2);
        dexMapItem.size = DexUtil.copyBytes(data_byte,4 , 4);
        dexMapItem.offset = DexUtil.copyBytes(data_byte,8 , 4);
        return dexMapItem;
    }

    public void readMapList(byte[] base_addr,int mapListoff){
        Main.dexType.dexMapLists.size = DexUtil.copyBytes(base_addr,mapListoff , 4);
        int mapListSize =  DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexMapLists.size));
        for(int i=0;i <mapListSize;i++){
            Main.dexType.dexMapLists.list.add(readDexMapItem(DexUtil.copyBytes(base_addr,mapListoff +4+ (i*12),12)));
        }
    }


}
