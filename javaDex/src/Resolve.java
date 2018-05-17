import java.util.ArrayList;
import java.util.Iterator;

public class Resolve {
    public static int str_num = 0;
    public static int typ_num = 0;
    public static int proto_num = 0;
    public static int field_num = 0;
    public static int method_num = 0;
    public static int def_num = 0;
    public static int map_num = 0;

    public void resolveHeader(){
        String magic = DexUtil.bytes2Hex(Main.dexType.dexHeader.magic);
        String checksum = DexUtil.bytes2HexLow(Main.dexType.dexHeader.checksum);
        String signature = DexUtil.bytes2Hex(Main.dexType.dexHeader.signature);
        String  fileSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.fileSize);
        String headerSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.headerSize);
        String  endianTag = DexUtil.bytes2HexLow(Main.dexType.dexHeader.endianTag);
        String linkSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.linkSize);
        String  linkOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.linkOff);
        String  mapOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.mapOff);
        String  stringIdsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.stringIdsSize);
        String  stringIdsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.stringIdsOff);
        String  typeIdsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.typeIdsSize);
        String typeIdsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.typeIdsOff);
        String  protoIdsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.protoIdsSize);
        String  protoIdsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.protoIdsOff);
        String  fieldIdsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.fieldIdsSize);
        String  fieldIdsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.fieldIdsOff);
        String  methodIdsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.methodIdsSize);
        String  methodIdsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.methodIdsOff);
        String  classDefsSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.classDefsSize);
        String  classDefsOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.classDefsOff);
        String  dataSize = DexUtil.bytes2HexLow(Main.dexType.dexHeader.dataSize);
        String  dataOff = DexUtil.bytes2HexLow(Main.dexType.dexHeader.dataOff);;

        System.out.println("============Resolve Header============");
        System.out.println("magic:             0x" + magic);
        System.out.println("cheksum:           0x" + checksum);
        System.out.println("signature:         0x" + signature);
        System.out.println("fileSize:            " + DexUtil.hexStr2Int(fileSize));
        System.out.println("headerSize:          " + DexUtil.hexStr2Int(headerSize));
        System.out.println("endianTag:         0x" + endianTag);
        System.out.println("linkSize:            " + DexUtil.hexStr2Int(linkSize));
        System.out.println("linkOff:           0x" + linkOff);
        System.out.println("mapOff:            0x" + mapOff);
        System.out.println("stringIdsSize:       " + DexUtil.hexStr2Int(stringIdsSize));
        System.out.println("stringIdsOff:      0x" + stringIdsOff);
        System.out.println("typeIdsSize:         " + DexUtil.hexStr2Int(typeIdsSize));
        System.out.println("typeIdsOff:        0x" + typeIdsOff);
        System.out.println("protoIdsSize:        " + DexUtil.hexStr2Int(protoIdsSize));
        System.out.println("protoIdsOff:       0x" + protoIdsOff);
        System.out.println("fieldIdsSize:        " + DexUtil.hexStr2Int(fieldIdsSize));
        System.out.println("fieldIdsOff:       0x" + fieldIdsOff);
        System.out.println("methodIdsSize:       " + DexUtil.hexStr2Int(methodIdsSize));
        System.out.println("methodIdsOff:      0x" + methodIdsOff);
        System.out.println("classDefsSize:       " + DexUtil.hexStr2Int(classDefsSize));
        System.out.println("classDefsOff:      0x" + classDefsOff);
        System.out.println("dataSize:            " + DexUtil.hexStr2Int(dataSize));
        System.out.println("dataOff:           0x" + dataOff);
    }

    public String resoveString(byte[] base_addr,int string_off){
        //MUTF-8编码规则，头部为字符串长度;
        int strLength = DexUtil.hexStr2Int(DexUtil.bytes2Hex(DexUtil.copyBytes(base_addr,string_off,1)));
        String str =DexUtil.hex2Asc(DexUtil.bytes2Hex(DexUtil.copyBytes(base_addr,string_off+1,strLength)));
        System.out.println("  "+str_num+"        "+str);
        str_num += 1;
        return str;
    }

    public void resoveStingList(byte[] base_addr){
        System.out.println("============Resolve String List============");
        System.out.println("The string list length is :" + Main.dexType.dexStringId.size());
        System.out.println("The string list is:");
        Iterator<DexType.DexStringId> dexStrList =Main.dexType.dexStringId.iterator();
        while(dexStrList.hasNext()){
            //这里读到了Sting的偏移
            int dexStingAddr =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexStrList.next().stringDataOff));
            Main.dexType.dexStringList.add(resoveString(base_addr,dexStingAddr));
        }
    }

    public void resoveTypeList(){
        System.out.println("============Resolve Type List============");
        System.out.println("The type list length is :" + Main.dexType.dexTypeId.size());
        System.out.println("The type list is:");
        Iterator<DexType.DexTypeId> dexTypList =Main.dexType.dexTypeId.iterator();
        while(dexTypList.hasNext()){
            //这里读到了Type的字段
            int typeIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexTypList.next().descriptorIdx));
            String type = Main.dexType.dexStringList.get(typeIndex);
            Main.dexType.dexTypeList.add(type);
            System.out.println("  #"+typ_num+"        "+type);
            typ_num += 1;
        }
    }

    public void resoveProtoList(byte[] base_addr,ReadDex readDex){
        System.out.println("============Resolve Proto List============");
        System.out.println("The proto list length is :" + Main.dexType.dexProtoId.size());
        System.out.println("The proto list is:");
        Iterator<DexType.DexProtoId> dexTypList =Main.dexType.dexProtoId.iterator();
        int para_tmp = 0;
        while(dexTypList.hasNext()){
            DexType.DexProtoId prototmp =dexTypList.next();
            String typeList = "";
            //shortyIdx字段解析
            int strIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(prototmp.shortyIdx));
            String str = Main.dexType.dexStringList.get(strIndex);
//            typeList = typeList +str;
            Main.dexType.dexProtoIdString.add(str);
            //returnTypeIdx字段解析
            int typeIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(prototmp.returnTypeIdx));
            String type = Main.dexType.dexTypeList.get(typeIndex);
            typeList = typeList +" "+type + "(";
            Main.dexType.dexProtoIdType.add(type);
            //parametersOff字段解析
            int paraIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(prototmp.parametersOff));
            if(paraIndex != 0){
                readDex.readDexTypeList(base_addr,paraIndex);
                int itemSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexTypeLists.get(para_tmp).size));
                for (int z =0;z<itemSize;z++){
                    typeList += Main.dexType.dexTypeList.get(DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexTypeLists.get(para_tmp).list.get(z).typeIdx)));
                    typeList +=")";
                }
                para_tmp += 1;
            }else{
                typeList +="()";
            }
            Main.dexType.dexProtoList.add(typeList);
            System.out.println("  #"+proto_num+"        "+typeList);
            proto_num += 1;
        }
    }

    public void resoveFieldList(){
        System.out.println("============Resolve Field List============");
        System.out.println("The Field list length is :" + Main.dexType.dexFieldId.size());
        System.out.println("The Field list is:");
        Iterator<DexType.DexFieldId> dexFieldList =Main.dexType.dexFieldId.iterator();
        while(dexFieldList.hasNext()){
            DexType.DexFieldId dexFieldItem =dexFieldList.next();
            String tmp = "";
            //这里读到字段
            int classIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexFieldItem.classIdx));
            String classtype = Main.dexType.dexTypeList.get(classIndex);

            int typeIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexFieldItem.typeIdx));
            String fieldType = Main.dexType.dexTypeList.get(typeIndex);

            int nameIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexFieldItem.nameIdx));
            String fieldName = Main.dexType.dexStringList.get(nameIndex);

            tmp =classtype + " " +fieldType + " " +fieldName;

            Main.dexType.dexFieldList.add(tmp);
            System.out.println("  #"+field_num+"        "+tmp);
            field_num += 1;
        }
    }

    public void resoveMethodList(){
        System.out.println("============Resolve Method List============");
        System.out.println("The Method list length is :" + Main.dexType.dexMethodId.size());
        System.out.println("The Method list is:");
        Iterator<DexType.DexMethodId> dexMethodList =Main.dexType.dexMethodId.iterator();
        while(dexMethodList.hasNext()){
            DexType.DexMethodId dexMethodItem =dexMethodList.next();
            String tmp = "";
            //这里读到字段
            int classIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMethodItem.classIdx));
            String classtype = Main.dexType.dexTypeList.get(classIndex);

            int protoIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMethodItem.protoIdx));
            String protoType = Main.dexType.dexProtoList.get(protoIndex);

            int nameIndex =DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMethodItem.nameIdx));
            String methodName = Main.dexType.dexStringList.get(nameIndex);

            tmp =classtype + " " +protoType + " " +methodName;

            Main.dexType.dexMethodList.add(tmp);
            System.out.println("  #"+method_num+"        "+tmp);
            method_num += 1;
        }
    }

    public void resoveClassDefList(byte[] base_addr ,ReadDex readDex){
        System.out.println("============Resolve ClassDef List============");
        System.out.println("The ClassDef list length is :" + Main.dexType.dexClassDefs.size());
        System.out.println("The ClassDef list is:");
        Iterator<DexType.DexClassDef> dexClassDefList =Main.dexType.dexClassDefs.iterator();
        while(dexClassDefList.hasNext()){
            System.out.println("----------------------------------------------------------------");
            System.out.println("        def#"+def_num +" :  ");
            DexType.DexClassDef dexClassDefItem =dexClassDefList.next();
            //这里读到字段
            int classIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.classIdx));
            String classtype = Main.dexType.dexTypeList.get(classIndex);
            System.out.println("        class type : " +classtype);

            int flagIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.accessFlags));
            String accessFlags = DexUtil.accessFlags(flagIndex);
            System.out.println("        access flag : " +accessFlags);

            int superIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.superclassIdx));
            String superType = Main.dexType.dexTypeList.get(superIndex);
            System.out.println("        super type : " +superType);

            int interIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.interfacesOff));
            if(interIndex != 0){
                System.out.println("        interfacesOff : " + interIndex);
            }

            int sourceIndex = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.sourceFileIdx));
            String sourceName = Main.dexType.dexStringList.get(sourceIndex);
            System.out.println("        source name : " + sourceName);

            String annotationsOff = DexUtil.bytes2HexLow(dexClassDefItem.annotationsOff);
            System.out.println("        annotationsOff : 0x" +annotationsOff);

            String classDataOff = DexUtil.bytes2HexLow(dexClassDefItem.classDataOff);
            System.out.println("        classDataOff : 0x" +classDataOff);
            if(!classDataOff.equals("0")){
                resoveClassDefData(base_addr ,DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexClassDefItem.classDataOff)) ,readDex);
            }


            String staticValuesOff = DexUtil.bytes2HexLow(dexClassDefItem.staticValuesOff);
            System.out.println("        staticValuesOff : 0x" +staticValuesOff);

            def_num += 1;
        }
    }

    public void resoveClassDefData(byte[] base_addr, int data_off ,ReadDex readDex){
        System.out.println("            ------------Resolve ClassDefData---------------");
        readDex.readClassDefData(base_addr,data_off);
        Iterator<DexType.DexClassData> dexClassData =Main.dexType.dexClassData.iterator();

        while(dexClassData.hasNext()){
            DexType.DexClassData dexClassDataItem =dexClassData.next();
            //打印静态字段
            int staFieldSize = DexUtil.decodeUleb128(dexClassDataItem.header.iterator().next().staticFieldsSize);
            System.out.println("            the static field number is " + staFieldSize);
            for(int t =0;t<staFieldSize;t++){
                DexType.DexField staField = dexClassDataItem.staticFields.iterator().next();
                int staFieldIndex = DexUtil.decodeUleb128(staField.fieldIdx);
                String staFieldStr = Main.dexType.dexFieldList.get(staFieldIndex);
                String acceFlag = DexUtil.accessFlags(DexUtil.decodeUleb128(staField.accessFlags));
                System.out.println("              #"+ t +"  "+staFieldStr+"  "+acceFlag);
            }

            //打印实例字段
            int insFieldSize = DexUtil.decodeUleb128(dexClassDataItem.header.iterator().next().instanceFieldsSize);
            System.out.println("            the instance field number is " + insFieldSize);
            for(int z =0;z<insFieldSize;z++){
                DexType.DexField insField = dexClassDataItem.instanceFields.iterator().next();
                int insFieldIndex = DexUtil.decodeUleb128(insField.fieldIdx);
                String insFieldStr = Main.dexType.dexFieldList.get(insFieldIndex);
                String acceFlag = DexUtil.accessFlags(DexUtil.decodeUleb128(insField.accessFlags));
                System.out.println("                  #"+ z +"  "+insFieldStr+"  "+acceFlag);
            }

            //打印直接方法
            int dirMethodSize = DexUtil.decodeUleb128(dexClassDataItem.header.iterator().next().directMethodsSize);
            System.out.println("            the direct method number is " + dirMethodSize);
            for(int k =0;k<dirMethodSize;k++){
                DexType.DexMethod dirMethod = dexClassDataItem.directMethods.iterator().next();
                int dirMethodIndex = DexUtil.decodeUleb128(dirMethod.methodIdx);
                String dirMethodStr = Main.dexType.dexMethodList.get(dirMethodIndex);
                String acceFlag = DexUtil.accessFlags(DexUtil.decodeUleb128(dirMethod.accessFlags));
                int dirCodeOff = DexUtil.decodeUleb128(dirMethod.codeOff);
                System.out.println("                  #"+ k +"  "+dirMethodStr+"  "+acceFlag);
                System.out.println("                     codeOff: "+ dirCodeOff);
            }

            //打印虚方法
            int virMethodSize = DexUtil.decodeUleb128(dexClassDataItem.header.iterator().next().virtualMethodsSize);
            System.out.println("            the virtual method number is " + virMethodSize);
            for(int j =0;j<virMethodSize;j++){
                DexType.DexMethod virMethod = dexClassDataItem.virtualMethods.iterator().next();
                int virMethodIndex = DexUtil.decodeUleb128(virMethod.methodIdx);
                String virMethodStr = Main.dexType.dexMethodList.get(virMethodIndex);
                String acceFlag = DexUtil.accessFlags(DexUtil.decodeUleb128(virMethod.accessFlags));
                int virCodeOff = DexUtil.decodeUleb128(virMethod.codeOff);
                System.out.println("                  #"+ j +"  "+virMethodStr+"  "+acceFlag);
                System.out.println("                     codeOff: "+ virCodeOff);
            }

        }
        System.out.println("            ------------ClassDefData  End  ---------------");
    }

    public void resolveMapList(){
        System.out.println("============Resolve Map List============");
        int mapSize = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(Main.dexType.dexMapLists.size));
        System.out.println("The Map list length is :" + mapSize);
        System.out.println("The Map list is:");

        Iterator<DexType.DexMapItem> dexMapItem =Main.dexType.dexMapLists.list.iterator();
        while(dexMapItem.hasNext()){
            DexType.DexMapItem dexMapItemIter = dexMapItem.next();
            String mapType =  DexUtil.itemType(DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMapItemIter.type)));
            int mapUnused = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMapItemIter.unused));
            int mapnum = DexUtil.hexStr2Int(DexUtil.bytes2HexLow(dexMapItemIter.size));
            String  mapoff = DexUtil.bytes2HexLow(dexMapItemIter.offset);
            System.out.println("  #"+map_num+"        "+mapType);
            System.out.println("    unused:"+"  "+mapUnused);
            System.out.println("    size:"+"    "+mapnum);
            System.out.println("    offset:"+"  0x"+mapoff);
            map_num += 1;
        }
    }

}
