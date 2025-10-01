# 基于Python的WITRN HID通用API

![version](https://img.shields.io/badge/Version-pre0.1-green)

## 项目介绍

该项目提供面向Python的接收WITRN HID数据流的通用API，仅需要导入项目下的 `core.py` 就可以开箱使用。

当前版本为预览版，可能存在许多问题，您可以向本项目反馈issue，暂不接受PR，感谢您的支持。

## 项目进度&画饼

目前已完成针对维简K2（V3.9+）的常规HID数据流的解析，包含Ah、Wh、记录时长、本次通电时长、D+电压、D-电压、外接温度、电压、电流、记录组别、CC1电压、CC2电压信息。

目前已完成针对维简K2（V3.9+）的PD HID数据流的部分解析，可以解析每条PD消息的除Data以外的内容，可以解析Source_Capabilities和Request的Data内容（即SPR PDO和SPR RDO内容），可以保存最后一个PDO内容。

预计在国庆完成对所有Data Message Type的解析Orz

## 数据结构

请仔细阅读以下内容确保您能正确的调用API。

### 元数据

任何经过解析的内容都将以元数据进行打包，元数据的基本结构如下

| 属性    | 类型           | 作用                                 |
| ------- | -------------- | ------------------------------------ |
| raw     | str/uint8 list | 当前元数据的二进制值或uint8 list     |
| bit_loc | tuple/int      | 当前元数据在上一层的比特位置         |
| field   | str            | 当前元数据字段名                     |
| value   | any            | 当前元数据字段值或是下一层元数据list |

代码实现：

```python
class metadata:
    def __init__(self, raw=None, bit_loc=None, field=None, value=None):
        self.raw = raw
        self.bit_loc = bit_loc
        self.field = field
        self.value = value

    def __str__(self):
        return f"{self.value}"
    
    def __repr__(self):
        return f"{self.field}: {self.value}"
```

元数据修改了默认的 `__str__` 和 `__repr__` 函数，使得打印元数据时返回其 `value` ，交互元数据时返回 `field` :  `value` 。

对于元数据的`value`为list的情况，还会单独为其映射list内元数据的{ `field` : 元数据}字典，并修改了默认的 `__getitem__` 函数，方便以 `field` 为关键字查找元数据，也可以使用索引查找元数据。

代码实现：
```python
class msg(metadata):
    def __init__(self, raw=None, bit_loc=None, field=None, value=None):
        super().__init__(raw, bit_loc, field)
        self.value = [
            metadata(...)
            metadata(...)
        ]
    	
        self.field_map = {m.field: m for m in self.value}
        if "Reserved" in self.field_map:
            del self.field_map["Reserved"]

    def __getitem__(self, field) -> metadata:
        if isinstance(field, str):
            return self.field_map.get(field, None)
        else:
            return self.value[field]
```



### 常规HID消息

常规HID消息解析时，每条消息将打包成一个元数据，其 `raw` 保存原始的uint8 list， `bit_loc` 保存(0, 511)即整条HID消息的从头到尾的比特位置， `field` 固定保存"general"， `value` 保存一个元数据list。

常规HID消息的 `value` 进行下一步解析，组成Ah、Wh、记录时长等的元数据 list，list中的每个元数据的 `raw` 保存该元数据的原始二进制值， `bit_loc` 保存该元数据在HID消息所占的比特位置，`field`保存该元数据的字段名， `value` 保存该元数据的字段值。例如保存Ah的元数据为：

```
raw = '01000001011000011101001101101011'
bit_loc = (112, 143)
field = 'Ah'
value = '14.114115715026855Ah'
```

### PD HID消息

PD HID消息将按层解析，第一层为HID消息层

| raw            | bit_loc               | field | value            |
| -------------- | --------------------- | ----- | ---------------- |
| 原始uint8 list | 有效的所有HID比特位置 | "pd"  | 下一层元数据list |

第二层为PD消息层，包含4或5个元数据

|      | field  | value                                |
| ---- | ------ | ------------------------------------ |
|      | Length | PD消息长度（包含SOP*）（单位：字节） |
|      | SOP*   |                                      |

