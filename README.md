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

对于元数据的`value`为list的情况，还会单独为其映射list内元数据的{ `field` : 元数据}字典，并修改了默认的 `__getitem__` 函数，方便以 `field` 为关键字查找元数据，也可以使用索引查找元数据。如果是需要字段值则对元数据使用 `.value` 获取。

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

| raw            | bit_loc               | field | value                |
| -------------- | --------------------- | ----- | -------------------- |
| 原始uint8 list | 有效的所有HID比特位置 | pd    | PD消息（元数据list） |

该层 `value` 包含3或4或5个元数据的list，组成第二层PD消息层，具体如下

| field                     | value                        |
| ------------------------- | ---------------------------- |
| Length                    | PD消息长度                   |
| SOP*                      | SOP类型                      |
| Message Header            | PD消息头（元数据list）       |
| [Extended Message Header] | [PD扩展消息头（元数据list）] |
| [Data Objects/Data Block] | [PD消息数据（元数据list）]   |

需要注意的是PD消息的单个逻辑内容是以小端存储，但是整条PD消息又是以大端存储，所以除非是单个逻辑内容的 `raw` 将以小端转换成二进制值，否则 `raw` 将以大端转换成二进制值。以第二层为例，Length字段的 `raw` 将以小端转换，但是Message Header字段的 `raw` 将以大端转换。

```
小端转换：0x14A5 -> 0b1010010100010100
大端转换：0x14A5 -> 0b0001010010100101
```

Message Header、[Extended Message Header]、[Data Objects/Data Block]的 `value` 均属于第三层。从本层开始， `bit_loc` 、 `field` 、 `value` 将严格按照USB-IF制定的PD规范来解析， `value` 的具体值将解析成可用值，例如电压电流值（带单位，str类型），Data Objects数量（int类型），是否扩展（bool类型），如果您需要二进制、十进制、十六进制值，可以直接从 `raw` 转换取得，注意前文提到的大小端问题。

第三层中只有[Data Objects/Data Block]的 `value` 包含第四层，不过内容复用度低且复杂，具体参考PD规范。

用文字描述PD HID消息的层级结构过于复杂也难以理解，简单来说任何数据都将以元数据格式打包，最小元数据单位即 `field` 为字段名、 `value` 为字段值。若干最小元数据构成一个数据包，该数据包也由元数据打包， `field` 为数据包名， `value` 为最小元数据list。若干数据包组合成更大的数据包结构，同样也由元数据打包，结构相同。如果你要具体的字段值，就要从打到小按层调取。

### WITRN_HID类

若要链接WITRN HID设备读取HID流并解包，需要您创建 `WITRN_HID` 类实例。该类结构实现不需要您掌握，其提供5种可调用方法。

首先是创建实例，您可以使用无参数方法创建实例默认连接K2设备，也可以传入vid、pid连接自定义设备，目前不支持多设备连接。

```python
dev = WITRN_HID()
dev = WITRN_HID(vid, pid)
```

创建实例会默认连接设备并打开HID流，无需手动开启。

`read_data()` 方法将获取从当前时刻后HID流中的第一个完整HID消息，返回uint8 list，并且在实例内默认保存获取时刻的时间戳（分辨率0.001s）和HID消息内容，保存到下次调用该方法时被覆盖。实例不会为你维护一个HID消息缓存栈，请您自行维护。

`general_unpack()` 方法将解析常规HID消息，如果不提供参数则默认解析实例内保存的HID消息，返回时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回解析完的元数据。

`pd_unpack()` 方法将解析PD HID消息，如果不提供参数则默认解析实例内保存的HID消息，返回时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回解析完的元数据。

`auto_unpack()` 方法将自动分析HID消息类型并解析，如果不提供参数则默认解析实例内保存的HID消息，返回时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回解析完的元数据。

注意，本API不会为您检查消息的正确性，如果解析失败则会直接break报错，后续可能会考虑检查数据合法性并提供break内容。

`close()` 方法将关闭实例的HID连接。
