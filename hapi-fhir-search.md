**Hapi Fhir**

Для поиска уязвимости предлагается взять последнюю версию библиотеки: https://github.com/hapifhir/hapi-fhir

Для поиска уязвимостей будем использовать CodeQL с правилами QLInspector:

```
import java
import libs.DangerousMethods
import libs.Source


private class DangerousExpression extends Expr {
  DangerousExpression() {
    ( this instanceof Call and this.(Call).getCallee() instanceof DangerousMethod ) or
    ( this instanceof LambdaExpr and this.(LambdaExpr).getExprBody().(MethodAccess).getMethod() instanceof DangerousMethod)
  }
}

private class CallsDangerousMethod extends Callable {
  CallsDangerousMethod(){
    exists(DangerousExpression de | de.getEnclosingCallable() = this)
  }
}

private class RecursiveCallToDangerousMethod extends Callable {
  RecursiveCallToDangerousMethod(){

    not this instanceof Sanitizer and

    /*
    /* can be commented for more results
    */
    (
      getDeclaringType().getASupertype*() instanceof TypeSerializable or
      this.isStatic()
    )

    and

    (
     this instanceof CallsDangerousMethod or
    exists(RecursiveCallToDangerousMethod unsafe | this.polyCalls(unsafe))
    )
  }

    /*
    /* linking a RecursiveCallToDangerousMethod to a DangerousExpression
    */
    DangerousExpression getDangerousExpression(){
    exists(DangerousExpression de | de.getEnclosingCallable() = this and result = de ) or
    exists(RecursiveCallToDangerousMethod unsafe | this.polyCalls(unsafe) and result = unsafe.(RecursiveCallToDangerousMethod).getDangerousExpression())
    }
}


/*
*
* global filter to block function in the chain,
* method names can be added when you found a false positive
*
*/
private class Sanitizer extends Callable {
  Sanitizer(){
    hasName([""])
  }
}


query predicate edges(ControlFlowNode node1, ControlFlowNode node2) {
    (node1.(MethodAccess).getMethod().getAPossibleImplementation() = node2 and node2 instanceof RecursiveCallToDangerousMethod) or
    (node2.(MethodAccess).getEnclosingCallable() = node1 and node1 instanceof RecursiveCallToDangerousMethod)
}

predicate hasCalls(RecursiveCallToDangerousMethod c0, RecursiveCallToDangerousMethod c1) {
    c0.polyCalls(c1) or exists(RecursiveCallToDangerousMethod unsafe | c0.polyCalls(unsafe) and hasCalls(unsafe, c1))
}
```

Начнем анализ с поисков sink-ов:

```
from Callable c0,  DangerousExpression de
where c0 instanceof RecursiveCallToDangerousMethod and
de.getEnclosingCallable() = c0
select c0, de
```

В результате поиска, было найдено 60 потенциально опасных мест:

![Search Result](/images/image_c.png)

Далее анализируем каждый sink:

**setProperty(...)**

Более половины всех sink-ов вызывают метода setProperty. Вызов этого метода может привести к нежелательным последствиям, однако если есть возможност ввести что-то хотя бы для ключа или для значения. Однако 99% всех вызовов данного метода вообще не дает возможности что-то ввести, а еще пара методов единолично лежит в public static функциях с возможностью выставить только значение для некоторых ключей, что явно говорит о том что это не уязвимость.

![Search Result](/images/image_d.png)

**new FileInputStream(...)**

Второй по популярность sink, имеет следующую проблему. FileInputStream переопределяет метод finalize(), как следствие объект не удаляется после закрытия, а очищается сборщиком мусора. Потенциально для приложений, которые запущены достаточно долго, это может привести к проблемам:

![Search Result](/images/image_e.png)

Классическое решение, использовать вместо FileInputStream функцию Files.newInputStream.

**invoke(...)**

В целом sink-и invoke, тоже достаточно безопасны. Например на следующем скриншоте, видно как invoke вызывается для сравнения двух объектов. При этом название метода, строго захардкожено и вероятность того, что через это место можно что-то сломать мала. 

![Search Result](/images/image_f.png)

Из интересного, один из методов invoke идет от метода с названием начинающимся на set. Это отсылает меня к уязвимости из fastjson - если мы включим autotype, то сможем вызвать функцию setServerConformanceProvider и invoke setRestfulServer. Опять же вызывается только захардкоженный метод. Внутри исходников библиотеки не удалось найти реализацию setRestfulServer. В качестве комментария указывается, что данный метод используется вместо констртуктора RestfulServer. Так же в коде есть N реализаций класса RestfulServer: 


![Search Result](/images/image_g.png)

Пример Poc-а с использованием fastjson:

```
public class Main {
    public static void main(String[] args){
        String poc = "{\"@type\":\"Lca.uhn.fhir.rest.server.RestfulServer;\",\"serverConformanceProvider\": {\"@type\": \"org.example.PocRestServer\" }}";
        Object obj = JSON.parse(poc, JSONReader.Feature.UseNativeObject,
                JSONReader.Feature.SupportAutoType);
        System.out.println(obj);
    }
}
```

```
public class PocRestServer {
    public void setRestfulServer(ca.uhn.fhir.rest.server.RestfulServer server){
      System.out.println("hello world");
    }
}
```

![Search Result](/images/image_h.png)
