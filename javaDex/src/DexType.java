import java.util.ArrayList;

public class DexType {

    public DexHeader dexHeader;
    public ArrayList<DexStringId> dexStringId;//所有字符串偏移存储
    public ArrayList<String > dexStringList;//所有字符串
    public ArrayList<DexTypeId> dexTypeId;//所有dexTypeID
    public ArrayList<String > dexTypeList;//所有type
    public ArrayList<DexProtoId> dexProtoId;//所有dexProtoID
    public ArrayList<String > dexProtoIdString;
    public ArrayList<String > dexProtoIdType;
    public ArrayList<DexTypeList> dexTypeLists;
    public ArrayList<String > dexProtoList;
    public ArrayList<DexFieldId> dexFieldId;
    public ArrayList<String > dexFieldList;
    public ArrayList<DexMethodId> dexMethodId;
    public ArrayList<String > dexMethodList;
    public ArrayList<DexClassDef> dexClassDefs;
    public ArrayList<DexClassData> dexClassData;
    public DexMapList dexMapLists;


    //构造函数
    DexType(){
        dexHeader = new DexHeader();

        dexStringId = new ArrayList<DexStringId>();
        dexStringList = new ArrayList<String >();

        dexTypeId =  new ArrayList<DexTypeId >();
        dexTypeList = new ArrayList<String >();

        dexProtoId = new ArrayList<DexProtoId>();
        dexProtoIdString = new ArrayList<String >();
        dexProtoIdType = new ArrayList<String >();
        dexTypeLists = new ArrayList<DexTypeList>();
        dexProtoList = new ArrayList<String >();

        dexFieldId = new ArrayList<DexFieldId>();
        dexFieldList = new ArrayList<String >();

        dexMethodId = new ArrayList<DexMethodId>();
        dexMethodList = new ArrayList<String >();

        dexClassDefs = new ArrayList<DexClassDef>();
        dexClassData = new ArrayList<DexClassData>();

        dexMapLists = new DexMapList();
    }

    /**
     * typedef struct DexHeader{
     *     u1 magic[8];                   //dex版本标识8个1字节
     *     u4 checksum;                   //adler32校验1个4字节
     *     u1 signature[kSHA1DigestLen];  //SHA-1哈希值
     *     u4 fileSize;                   //整个文件的大小
     *     u4 headerSize;                 //DexHeader的结构大小
     *     u4 endianTag;                  //字节序标记
     *     u4 linkSize;                   //链接段大小
     *     u4 linkOff;                    //链接段偏移
     *     u4 mapOff;                     //DexMapList的文件偏移
     *     u4 stringIdsSize;              //DexStringId的个数
     *     u4 stringIdsOff;               //DexStringId的文件偏移
     *     u4 typeIdsSize;                //DexTupeID的个数
     *     u4 typeIdsOff;                 //DexTypeId的文件偏移
     *     u4 protoIdsSize;               //DexProtoId的个数
     *     u4 protoIdsOff;                //DexProtoId的文件偏移
     *     u4 fieldIdsSize;               //DexFieldId的个数
     *     u4 fieldIdsOff;                //DexFieldId的文件偏移
     *     u4 methodIdsSize;              //DexMethodId的个数
     *     u4 methodIdsOff;               //DexMethodID的文件偏移
     *     u4 classDefsSize;              //DexClassDef的个数
     *     u4 classDefsOff;               //DexClassDef的文件偏移
     *     u4 dataSize;                   //数据段的大小
     *     u4 dataOff;                    //数据段的文件偏移
     * }
     */
    public class DexHeader{
        public byte[] magic = new byte[8];
        public byte[] checksum = new byte[4];
        public byte[] signature = new byte[20];
        public byte[] fileSize = new byte[4];
        public byte[] headerSize = new byte[4];
        public byte[] endianTag = new byte[4];
        public byte[] linkSize = new byte[4];
        public byte[] linkOff = new byte[4];
        public byte[] mapOff = new byte[4];
        public byte[] stringIdsSize = new byte[4];
        public byte[] stringIdsOff = new byte[4];
        public byte[] typeIdsSize = new byte[4];
        public byte[] typeIdsOff = new byte[4];
        public byte[] protoIdsSize = new byte[4];
        public byte[] protoIdsOff = new byte[4];
        public byte[] fieldIdsSize = new byte[4];
        public byte[] fieldIdsOff = new byte[4];
        public byte[] methodIdsSize = new byte[4];
        public byte[] methodIdsOff = new byte[4];
        public byte[] classDefsSize = new byte[4];
        public byte[] classDefsOff = new byte[4];
        public byte[] dataSize = new byte[4];
        public byte[] dataOff = new byte[4];
    }

    /**
     * typedef struct DexStringId{
     *      u4 stringDataOff;
     * }
     */
    public class DexStringId{
        public byte[] stringDataOff= new byte[4];
    }

    /**
     * typedef struct DexTypeId{
     *     u4 descriptorIdx;
     * }
     */
    public class DexTypeId{
        public byte[] descriptorIdx=new byte[4];
    }

    /**
     * typedef struct DexProtoId{
     *     u4 shortyIdx;
     *     u4 returnTypeIdx;
     *     u4 parametersOff;
     * }
     */
    public class DexProtoId{
        public byte[] shortyIdx=new byte[4];
        public byte[] returnTypeIdx=new byte[4];
        public byte[] parametersOff=new byte[4];
    }

    /**
     * typedef struct DexTypeItem{
     *     u2 typeIdx;
     * }
     */
    public class DexTypeItem{
        public byte[] typeIdx=new byte[2];
    }

    /**
     * typedef struct DexTypeList{
     *     u4 size;
     *     DexTypeItem list[11;
     * }
     */
    public class DexTypeList{
        public byte[] size=new byte[4];
        public ArrayList<DexTypeItem> list=new ArrayList<DexTypeItem>();
    }

    /**
     * typedef struct DexFieldId{
     *     u4 classIdx;
     *     u4 typeIdx;
     *     u4 nameIdx;
     * }
     */
    public class DexFieldId{
        public byte[] classIdx=new byte[4];
        public byte[] typeIdx=new byte[4];
        public byte[] nameIdx=new byte[4];
    }

    /**
     * typedef struct DexMethodId{
     *     u4 classIdx;
     *     u4 protoIdx;
     *     u4 nameIdx;
     * }
     */
    public class DexMethodId{
        public byte[] classIdx=new byte[4];
        public byte[] protoIdx=new byte[4];
        public byte[] nameIdx=new byte[4];
    }

    /**
     * typedef struct DexClassDef{
     *     u4 classIdx;
     *     u4 accessFlags;
     *     u4 superclassIdx;
     *     u4 interfacesOff;
     *     u4 sourceFileIdx;
     *     u4 annotationsOff;
     *     u4 classDataOff;
     *     u4 staticValuesOff;
     * }
     */
    public class DexClassDef{
        public byte[] classIdx=new byte[4];
        public byte[] accessFlags=new byte[4];
        public byte[] superclassIdx=new byte[4];
        public byte[] interfacesOff=new byte[4];
        public byte[] sourceFileIdx=new byte[4];
        public byte[] annotationsOff=new byte[4];
        public byte[] classDataOff=new byte[4];
        public byte[] staticValuesOff=new byte[4];

    }


    /**
     * typedef struct DexClassDataHeader{
     *     u4 staticFieldsSize;
     *     u4 instanceFieldsSize;
     *     u4 directMethodsSize;
     *     u4 virtualMethodsSize;
     * }
     */
    public class DexClassDataHeader{
        public byte[] staticFieldsSize = new byte[5];
        public byte[] instanceFieldsSize = new byte[5];
        public byte[] directMethodsSize = new byte[5];
        public byte[] virtualMethodsSize = new byte[5];

    }

    /**
     * typedef struct DexField{
     *     u4 fieldIdx;
     *     u4 accessFlags;
     * }
     */
    public class DexField{
        public byte[] fieldIdx = new byte[5];
        public byte[] accessFlags = new byte[5];
    }

    /**
     * typedef struct DexMethod{
     *     u4 methodIdx;
     *     u4 accessFlags;
     *     u4 codoOff;
     * }
     */
    public class DexMethod{
        public byte[] methodIdx = new byte[5];
        public byte[] accessFlags = new byte[5];
        public byte[] codeOff = new byte[5];
    }

    /**
     * typedef struct DexClassData{
     *     DexClassDataHeader header;
     *     DexField* staticFields;
     *     DexField* instanceFields;
     *     DexMethod* directMethods;
     *     DexMethod* virtualMethods
     * }
     */
    public class DexClassData{
        public ArrayList<DexClassDataHeader> header = new ArrayList<DexClassDataHeader>();
        public ArrayList<DexField> staticFields = new ArrayList<DexField>();
        public ArrayList<DexField> instanceFields = new ArrayList<DexField>();
        public ArrayList<DexMethod> directMethods = new ArrayList<DexMethod>();
        public ArrayList<DexMethod> virtualMethods = new ArrayList<DexMethod>();
    }

    /**
     * typedef struct DexMapItem{
     *     u2 type;
     *     u2 unused;
     *     u4 size;
     *     u4 offset;
     * }
     */
    public class DexMapItem{
        public byte[] type=new byte[2];
        public byte[] unused=new byte[2];
        public byte[] size=new byte[4];
        public byte[] offset=new byte[4];
    }

    /**
     * typedef struct DexMapList{
     *     u4 size;
     *     DexMapItem list[11;
     * }
     */
    public class DexMapList{
        public byte[] size=new byte[4];
        public ArrayList<DexMapItem> list=new ArrayList<DexMapItem>();
    }




}
