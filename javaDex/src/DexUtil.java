import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class DexUtil {

    //read dex file to bytes
    public static byte[] readFile(String fileName){
        InputStream in = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try{
            in = new FileInputStream(fileName);
            byte[] buf = new byte[1024];
            int length = 0;
            while((length = in.read(buf)) != -1){
                out.write(buf, 0, length);
            }
        }catch (Exception e1){
            e1.printStackTrace();
        }finally {
            if(in != null){
                try{
                    in.close();
                }catch (IOException e1){
                    e1.printStackTrace();
                }
            }
        }
        return out.toByteArray();
    }

    //copy Bytes from addr between start to length+start
    public static byte[] copyBytes(byte[] addr,int start,int length){
        byte[] destByte = new byte[length];
        for(int i=0;i<length;i++){
            destByte[i] = addr[start+i];
        }
        return destByte;
    }

    //bytes2Hex
    public static String bytes2Hex(byte[] bytes){
        final String HEX ="0123456789abcdef";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes){
            //取出这个字节的高4位
            sb.append(HEX.charAt((b >> 4) & 0x0f));
            //取出这个字节的低位，与0x0f与运算，得到一个0-15直接的数据，通过HEX.charAt(0-15)即为16进制数
            sb.append(HEX.charAt( b & 0x0f));
        }
        return sb.toString();
    }

    //betys2hex 小端读
    public static String bytes2HexLow(byte[] bytes){
        final String HEX ="0123456789abcdef";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i=bytes.length-1;i>=0;i--){
            byte b =bytes[i];
            //取出这个字节的高4位
            sb.append(HEX.charAt((b  >> 4) & 0x0f));
            //取出这个字节的低位，与0x0f与运算，得到一个0-15直接的数据，通过HEX.charAt(0-15)即为16进制数
            sb.append(HEX.charAt( b & 0x0f));
        }
        return sb.toString();
    }

    public static int hex2int(String hexStr){
        char[] str ={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        char[] hexs =hexStr.toCharArray();
        int n = 1;
        int hex=0;
        for(int i =hexStr.length();i > 0;i--){

            char tmp =hexs[i-1];
            for(int j =0;j<16;j++){
                if (str[j] ==tmp){
                    hex +=(j)*n;
                    break;
                }
            }
            n=n*16;
        }
        return hex;

    }

    public static int hexStr2Int(String hexStr){
        char[] hexs =hexStr.toCharArray();
        int number=0;
        for(int i=0;i <hexStr.length();i++){
            if(hexs[i]!='0'){
                number = i;
                break;
            }
        }
        String intHexStr = hexStr.substring(number,hexStr.length());
        int intStr =hex2int(intHexStr);
        return intStr;

    }

    public static String hex2Asc(String hex){

        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        //49204c6f7665204a617661 split into two characters 49, 20, 4c...
        for( int i=0; i<hex.length()-1; i+=2 ){

            //grab the hex in pairs
            String output = hex.substring(i, (i + 2));
            //convert hex to decimal
            int decimal = Integer.parseInt(output, 16);
            //convert the decimal to character
            sb.append((char)decimal);

            temp.append(decimal);
        }

        return sb.toString();
    }

    public static int decodeUleb128(byte[] byteAry){
        int index = 0,cur;
        int result = byteAry[index]&0xff;

        if(index < byteAry.length){
            result = byteAry[index]&0xff;
            index++;
            if(index < byteAry.length){
                cur =byteAry[index]&0xff;
                result = (result & 0x7f) | ((cur & 0x7f) << 7);
                index++;
                if(index < byteAry.length){
                    cur = byteAry[index];
                    result |=(cur & 0x7f) << 14;
                    index++;
                    if(index < byteAry.length){
                        cur = byteAry[index]&0xff;
                        result |= (cur & 0x7f) << 21;
                        index++;
                        if(index < byteAry.length){
                            cur = byteAry[4]&0xff;
                            result |= cur <<28;
                        }
                    }
                }
            }
        }

        return result;
    }

    //判断ULeb128读取几位，返回位数（1-5）
    public static int readULeb128(byte[] bytes_data){
        int offset = 1;
        byte[] tmp_byte = copyBytes(bytes_data,0,1);
        while(hexStr2Int(bytes2Hex(tmp_byte)) > 0x7f){
            tmp_byte = copyBytes(bytes_data,offset,1);
            offset += 1;
        }
        if(offset > 5){
            System.out.println("ERRO:the ULeb128 read wrong!");
            System.exit(0);
        }
        return offset;
    }

    public static String accessFlag(int flag){
        String accessFlags ="";
            switch (flag) {
                case 0x1:
                    accessFlags += "ACC_PUBLIC ";
                    break;
                case 0x2:
                    accessFlags += "ACC_PRIVATE ";
                    break;
                case 0x4:
                    accessFlags += "ACC_PROTECTED ";
                    break;
                case 0x8:
                    accessFlags += "ACC_STATIC ";
                    break;
                case 0x10:
                    accessFlags += "ACC_FINAL ";
                    break;
                case 0x20:
                    accessFlags += "ACC_SYNCHRONIZED ";
                    break;
                case 0x40:
                    accessFlags += "ACC_VOLATILE ";
                    break;
                case 0x80:
                    accessFlags += "ACC_TRANSIENT ";
                    break;
                case 0x100:
                    accessFlags += "ACC_NATIVE ";
                    break;
                case 0x200:
                    accessFlags += "ACC_INTERFACE ";
                    break;
                case 0x400:
                    accessFlags += "ACC_ABSTRACT ";
                    break;
                case 0x800:
                    accessFlags += "ACC_STRICT ";
                    break;
                case 0x1000:
                    accessFlags += "ACC_SYNTHETIC ";
                    break;
                case 0x2000:
                    accessFlags += "ACC_ANNOTATION ";
                    break;
                case 0x4000:
                    accessFlags += "ACC_ENUM ";
                    break;
                case 0x10000:
                    accessFlags += "ACC_CONSTRUCTOR ";
                    break;
                case 0x20000:
                    accessFlags += "ACC_DECLARED_SYNCHRONIZED ";
                    break;
            }
        return accessFlags;
    }

    public static String accessFlags(int flag){
        String accessFlags ="";
        String numStr =Integer.toBinaryString(flag);

        for(int i=0;i<numStr.length();i++){
            if(numStr.charAt(i)!= '0'){
                int num = (int)Math.pow(2,i);
                accessFlags += accessFlag(num);
            }
        }

        return accessFlags;
    }

    public static String itemType(int flag){
        String type=null;
        switch (flag) {
            case 0:
                type = "TYPE_HEADER_ITEM";
                break;
            case 1:
                type = "TYPE_STRING_ID_ITEM";
                break;
            case 2:
                type = "TYPE_TYPE_ID_ITEM";
                break;
            case 3:
                type = "TYPE_PROTO_ID_ITEM";
                break;
            case 4:
                type = "TYPE_FIELD_ID_ITEM";
                break;
            case 5:
                type = "TYPE_METHOD_ID_ITEM";
                break;
            case 6:
                type = "TYPE_CLASS_DEF_ITEM";
                break;
            case 0x2002:
                type = "TYPE_STRING_DATA_ITEM";
                break;
            case 0x1001:
                type = "TYPE_TYPE_LIST";
                break;
            case 0x2004:
                type = "TYPE_ANNOTATION_ITEM";
                break;
            case 0x1003:
                type = "TYPE_ANNOTATION_SET_ITEM";
                break;
            case 0x2006:
                type = "TYPE_ANNOTATIONS_DIRECTORY_ITEM";
                break;
            case 0x2003:
                type = "TYPE_DEBUG_INFO_ITEM";
                break;
            case 0x2001:
                type = "TYPE_CODE_ITEM";
                break;
            case 0x2000:
                type = "TYPE_CLASS_DATA_ITEM";
                break;
            case 0x1000:
                type = "TYPE_MAP_ITEM";
                break;
        }
        return type;
    }

}
