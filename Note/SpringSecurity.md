# SpringSecurity



# 一、 简介

​     SpringSecurity安全管理框架。相比于另外一个安全框架Shiro，它提供了更丰富的功能，社区资源也比Shiro丰富。



​    **一般Web应用需要进行认证和授权，而认证和收取那也是安全框架的核心功能。**

​     **认证：**验证当前访问系统的是不是本系统的用户，并且要确认具体是哪个用户

​     **授权：**经过认证后判断当前用户是否有权限进行某个操作





# 二、快速入门



## 2.1 maven坐标

```xml
<!--引入SpringSecurity-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```



引入依赖后，我们在尝试去访问之前的接口就会自动跳转到一个**SpringSecurity的默认登录界面，默认用户名是User，密码会输出在控制**台

**必须登陆之后才能对接口进行访问**



## 2.2 访问请求



如下所示：  当我们输入localhost:8080/hello/hello后，并不能访问我们的请求

```java
@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping("/hello")
    private String hello(){
        return "hello";
    }

}
```



而是出现了下面这个页面，这个登录页面后面是可以换掉的，前后端分离的话不需要登录页，留一个登录接口就可以了。

默认的用户名： user  默认密码： 会在控制台输出

![image-20230426232433904](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426232433904.png)



并且控制台也出现了一串数字

![image-20230426232555639](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426232555639.png)



使用Apifox也出现unauthorized，没有权限

![image-20230426232631828](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426232631828.png)



当我们在页面输入用户名以及密码后，会获得我们请求的结果

![image-20230426233025167](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426233025167.png)







# 三、认证与授权



##  3.1 认证



###   3.1.1 登录检验流程

核心依赖token(加密后的一个字符串)，通过判断是否携带token，可以判断是不是系统的用户，也可以判断是哪一个用户。



![image-20230426233811243](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426233811243.png)



### 3.1.2 SpringSecurity 完整流程

SpringSecurity的原理其实就是一个过滤器链，内部包含了提供各种功能的过滤器

![image-20230426235249540](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426235249540.png)



总共有15个过滤器

![image-20230427001159369](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427001159369.png)





- **UsernamePasswordAuthenticationFilter:**

    负责处理我们在登陆页面填写了用户名密码后的登陆请求。入门案例的**认证工作**主要由它负责。

  

- **ExceptionTranslationFilter: **

    处理认证和授权中**出现的所有异常，做统一的处理。**

    处理过滤器中抛出的任何AccessDeniedException和AuthenticationException。



- **FilterSecuritylnterceptor:**

  **负责授权、负责权限校验的过滤器**。并且判断当前访问的资源需要什么权限，访问的具有什么权限，是否能够访问。





###   3.1.3 认证流程详解

![image-20230427001540666](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427001540666.png)



 **概念速查:**

- Authentication接口: 它的实现类，表示当前访问系统的用户，封装了用户相关信息。

  

- AuthenticationManager接口: 定义了认证Authentication的方法

  

- UserDetailsService接口: 加载用户特定数据的核心接口。里面定义了一个根据用户名查询用户信息的方法。

  

- UserDetails接口: 提供核心用户信息，通过UserDetailsservice根据用户名获取处理的用户信息要封装成

  

- UserDetails对象返回。然后将这些信息封装到Authentication对象中。





##  3.2 授权









