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

​       下图中的第一步，我们登录提交的用户名和密码不会提交到这里，我们会自己写一个controller，然后在controller当中调用ProviderManager。

​      下图中的第五步，我们要改成从数据库里面进行查询(下图中是在内存中查找)，只需要把UserDetailsService接口的实现类InMemoryUserDetailsManager这个实现类换成其他的实现类就好了，然后再调用这个实现类。

![image-20230427140309743](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427140309743.png)

 **概念速查:**

- Authentication接口: 它的实现类，表示当前访问系统的用户，封装了用户相关信息。

  

- AuthenticationManager接口: 定义了认证Authentication的方法

  

- UserDetailsService接口: 加载用户特定数据的核心接口。里面定义了一个根据用户名查询用户信息的方法。

  

- UserDetails接口: 提供核心用户信息，通过UserDetailsservice根据用户名获取处理的用户信息要封装成

  

- UserDetails对象返回。然后将这些信息封装到Authentication对象中。



**分析后的最终结果：**

![image-20230427141117915](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427141117915.png)



补充“登录接口”返回到前端之前的描述：

​      如果认证通过，使用用户id生成一个jwt，然后用userid作为key，用户信息作为value存入Redis。此处的token方便我们之后**校验和授权。**





### 3.1.4  校验

 我们要对某些请求进行校验，看看是否会有请求的权限。

我们需要自己定义过滤器，解析前端带过来的token。

![image-20230427141528840](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427141528840.png)



**思考：**

   **JWT 认证过滤器中获取userid后怎么获取到完成的用户信息？**

​       也可以访问Service层再访问数据库，但是每次请求都访问数据库会太浪费时间，对数据库压力大。

​       这个地方我们可以加一个Redis，从缓存中获取，Redis中的信息我们可以每隔一段时间就更新。



​    **那我们什么时候把token存入到Redis呢？**

​      在登录成功后。







  ### 3.1.5 要解决的问题

-  **登录：**

​        ① 自定义登录接口 

​                调用ProviderManager的方法进行认证，如果认证通过生成就 jwt，并把信息存入Redis中

​        ② 自定义UserDetailsService 

​                在这个实现列中去查询数据库 



-  **检验：**

​        ① 自定义Jwt认证过滤器

​                获取token，解析token，获取其中的userid，从Redis中获取用户信息，存入SecurityContextHolder中



> SecurityContextHolder 对象作用：
>
> ​      作用是保存和管理当前执行线程的安全上下文信息。安全上下文信息包括当前执行线程的身份验证、授权信息等安全相关的上下文数据。
>
> 
>
> SecurityContextHolder提供了一组静态方法来访问和管理当前执行线程的安全上下文信息，如：
>
> - getContext()：获取当前执行线程的安全上下文对象。
> - setContext(context)：设置当前执行线程的安全上下文对象。
> - createEmptyContext()：创建一个新的空的安全上下文对象。
> - clearContext()：清除当前执行线程的安全上下文对象。
>
> 
>
> ​      在Spring Security中，开发人员可以通过SecurityContextHolder在应用程序任何地方访问和使用当前用户的身份和权限信息，以便实现安全检查和控制。例如，在方法调用时，可以使用SecurityContextHolder获取当前用户的身份验证信息，并确保该用户具有执行该方法所需的所有必要权限，或者在记录日志时，可以使用SecurityContextHolder获取当前用户身份验证信息，将其添加到日志消息中，以便跟踪特定用户的操作历史。
>
> 



### 3.1.6 准备工作

①添加依赖

~~~~xml
        <!--redis依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <!--fastjson依赖-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.33</version>
        </dependency>
        <!--jwt依赖-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.0</version>
        </dependency>
~~~~

② 添加Redis相关配置

~~~~java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.util.Assert;
import java.nio.charset.Charset;

/**
 * Redis使用FastJson序列化
 * 
 * @author sg
 */
public class FastJsonRedisSerializer<T> implements RedisSerializer<T>
{

    public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

    private Class<T> clazz;

    static
    {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    public FastJsonRedisSerializer(Class<T> clazz)
    {
        super();
        this.clazz = clazz;
    }

    @Override
    public byte[] serialize(T t) throws SerializationException
    {
        if (t == null)
        {
            return new byte[0];
        }
        return JSON.toJSONString(t, SerializerFeature.WriteClassName).getBytes(DEFAULT_CHARSET);
    }

    @Override
    public T deserialize(byte[] bytes) throws SerializationException
    {
        if (bytes == null || bytes.length <= 0)
        {
            return null;
        }
        String str = new String(bytes, DEFAULT_CHARSET);

        return JSON.parseObject(str, clazz);
    }


    protected JavaType getJavaType(Class<?> clazz)
    {
        return TypeFactory.defaultInstance().constructType(clazz);
    }
}
~~~~

~~~~java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Bean
    @SuppressWarnings(value = { "unchecked", "rawtypes" })
    public RedisTemplate<Object, Object> redisTemplate(RedisConnectionFactory connectionFactory)
    {
        RedisTemplate<Object, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        FastJsonRedisSerializer serializer = new FastJsonRedisSerializer(Object.class);

        // 使用StringRedisSerializer来序列化和反序列化redis的key值
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        // Hash的key也采用StringRedisSerializer的序列化方式
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }
}
~~~~

③ 响应类

~~~~java
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * @Author 三更  B站： https://space.bilibili.com/663528522
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseResult<T> {
    /**
     * 状态码
     */
    private Integer code;
    /**
     * 提示信息，如果有错误时，前端可以获取该字段进行提示
     */
    private String msg;
    /**
     * 查询到的结果数据，
     */
    private T data;

    public ResponseResult(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public ResponseResult(Integer code, T data) {
        this.code = code;
        this.data = data;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public ResponseResult(Integer code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
}
~~~~

④工具类

~~~~java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * JWT工具类
 */
public class JwtUtil {

    //有效期为
    public static final Long JWT_TTL = 60 * 60 *1000L;// 60 * 60 *1000  一个小时
    //设置秘钥明文
    public static final String JWT_KEY = "sangeng";

    public static String getUUID(){
        String token = UUID.randomUUID().toString().replaceAll("-", "");
        return token;
    }
    
    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @return
     */
    public static String createJWT(String subject) {
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID());// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public static String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID());// 设置过期时间
        return builder.compact();
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if(ttlMillis==null){
            ttlMillis=JwtUtil.JWT_TTL;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setId(uuid)              //唯一的ID
                .setSubject(subject)   // 主题  可以是JSON数据
                .setIssuer("sg")     // 签发者
                .setIssuedAt(now)      // 签发时间
                .signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                .setExpiration(expDate);
    }

    /**
     * 创建token
     * @param id
     * @param subject
     * @param ttlMillis
     * @return
     */
    public static String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id);// 设置过期时间
        return builder.compact();
    }

    public static void main(String[] args) throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJjYWM2ZDVhZi1mNjVlLTQ0MDAtYjcxMi0zYWEwOGIyOTIwYjQiLCJzdWIiOiJzZyIsImlzcyI6InNnIiwiaWF0IjoxNjM4MTA2NzEyLCJleHAiOjE2MzgxMTAzMTJ9.JVsSbkP94wuczb4QryQbAke3ysBDIL5ou8fWsbt_ebg";
        Claims claims = parseJWT(token);
        System.out.println(claims);
    }

    /**
     * 生成加密后的秘钥 secretKey
     * @return
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }
    
    /**
     * 解析
     *
     * @param jwt
     * @return
     * @throws Exception
     */
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }


}
~~~~

~~~~java
import java.util.*;
import java.util.concurrent.TimeUnit;

@SuppressWarnings(value = { "unchecked", "rawtypes" })
@Component
public class RedisCache
{
    @Autowired
    public RedisTemplate redisTemplate;

    /**
     * 缓存基本的对象，Integer、String、实体类等
     *
     * @param key 缓存的键值
     * @param value 缓存的值
     */
    public <T> void setCacheObject(final String key, final T value)
    {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 缓存基本的对象，Integer、String、实体类等
     *
     * @param key 缓存的键值
     * @param value 缓存的值
     * @param timeout 时间
     * @param timeUnit 时间颗粒度
     */
    public <T> void setCacheObject(final String key, final T value, final Integer timeout, final TimeUnit timeUnit)
    {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 设置有效时间
     *
     * @param key Redis键
     * @param timeout 超时时间
     * @return true=设置成功；false=设置失败
     */
    public boolean expire(final String key, final long timeout)
    {
        return expire(key, timeout, TimeUnit.SECONDS);
    }

    /**
     * 设置有效时间
     *
     * @param key Redis键
     * @param timeout 超时时间
     * @param unit 时间单位
     * @return true=设置成功；false=设置失败
     */
    public boolean expire(final String key, final long timeout, final TimeUnit unit)
    {
        return redisTemplate.expire(key, timeout, unit);
    }

    /**
     * 获得缓存的基本对象。
     *
     * @param key 缓存键值
     * @return 缓存键值对应的数据
     */
    public <T> T getCacheObject(final String key)
    {
        ValueOperations<String, T> operation = redisTemplate.opsForValue();
        return operation.get(key);
    }

    /**
     * 删除单个对象
     *
     * @param key
     */
    public boolean deleteObject(final String key)
    {
        return redisTemplate.delete(key);
    }

    /**
     * 删除集合对象
     *
     * @param collection 多个对象
     * @return
     */
    public long deleteObject(final Collection collection)
    {
        return redisTemplate.delete(collection);
    }

    /**
     * 缓存List数据
     *
     * @param key 缓存的键值
     * @param dataList 待缓存的List数据
     * @return 缓存的对象
     */
    public <T> long setCacheList(final String key, final List<T> dataList)
    {
        Long count = redisTemplate.opsForList().rightPushAll(key, dataList);
        return count == null ? 0 : count;
    }

    /**
     * 获得缓存的list对象
     *
     * @param key 缓存的键值
     * @return 缓存键值对应的数据
     */
    public <T> List<T> getCacheList(final String key)
    {
        return redisTemplate.opsForList().range(key, 0, -1);
    }

    /**
     * 缓存Set
     *
     * @param key 缓存键值
     * @param dataSet 缓存的数据
     * @return 缓存数据的对象
     */
    public <T> BoundSetOperations<String, T> setCacheSet(final String key, final Set<T> dataSet)
    {
        BoundSetOperations<String, T> setOperation = redisTemplate.boundSetOps(key);
        Iterator<T> it = dataSet.iterator();
        while (it.hasNext())
        {
            setOperation.add(it.next());
        }
        return setOperation;
    }

    /**
     * 获得缓存的set
     *
     * @param key
     * @return
     */
    public <T> Set<T> getCacheSet(final String key)
    {
        return redisTemplate.opsForSet().members(key);
    }

    /**
     * 缓存Map
     *
     * @param key
     * @param dataMap
     */
    public <T> void setCacheMap(final String key, final Map<String, T> dataMap)
    {
        if (dataMap != null) {
            redisTemplate.opsForHash().putAll(key, dataMap);
        }
    }

    /**
     * 获得缓存的Map
     *
     * @param key
     * @return
     */
    public <T> Map<String, T> getCacheMap(final String key)
    {
        return redisTemplate.opsForHash().entries(key);
    }

    /**
     * 往Hash中存入数据
     *
     * @param key Redis键
     * @param hKey Hash键
     * @param value 值
     */
    public <T> void setCacheMapValue(final String key, final String hKey, final T value)
    {
        redisTemplate.opsForHash().put(key, hKey, value);
    }

    /**
     * 获取Hash中的数据
     *
     * @param key Redis键
     * @param hKey Hash键
     * @return Hash中的对象
     */
    public <T> T getCacheMapValue(final String key, final String hKey)
    {
        HashOperations<String, String, T> opsForHash = redisTemplate.opsForHash();
        return opsForHash.get(key, hKey);
    }

    /**
     * 删除Hash中的数据
     * 
     * @param key
     * @param hkey
     */
    public void delCacheMapValue(final String key, final String hkey)
    {
        HashOperations hashOperations = redisTemplate.opsForHash();
        hashOperations.delete(key, hkey);
    }

    /**
     * 获取多个Hash中的数据
     *
     * @param key Redis键
     * @param hKeys Hash键集合
     * @return Hash对象集合
     */
    public <T> List<T> getMultiCacheMapValue(final String key, final Collection<Object> hKeys)
    {
        return redisTemplate.opsForHash().multiGet(key, hKeys);
    }

    /**
     * 获得缓存的基本对象列表
     *
     * @param pattern 字符串前缀
     * @return 对象列表
     */
    public Collection<String> keys(final String pattern)
    {
        return redisTemplate.keys(pattern);
    }
}
~~~~

~~~~java
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class WebUtils
{
    /**
     * 将字符串渲染到客户端
     * 
     * @param response 渲染对象
     * @param string 待渲染的字符串
     * @return null
     */
    public static String renderString(HttpServletResponse response, String string) {
        try
        {
            response.setStatus(200);
            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");
            response.getWriter().print(string);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        return null;
    }
}
~~~~

⑤实体类

~~~~java
import java.io.Serializable;
import java.util.Date;


/**
 * 用户表(User)实体类
 *
 * @author 三更
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User implements Serializable {
    private static final long serialVersionUID = -40356785423868312L;
    
    /**
    * 主键
    */
    private Long id;
    /**
    * 用户名
    */
    private String userName;
    /**
    * 昵称
    */
    private String nickName;
    /**
    * 密码
    */
    private String password;
    /**
    * 账号状态（0正常 1停用）
    */
    private String status;
    /**
    * 邮箱
    */
    private String email;
    /**
    * 手机号
    */
    private String phonenumber;
    /**
    * 用户性别（0男，1女，2未知）
    */
    private String sex;
    /**
    * 头像
    */
    private String avatar;
    /**
    * 用户类型（0管理员，1普通用户）
    */
    private String userType;
    /**
    * 创建人的用户id
    */
    private Long createBy;
    /**
    * 创建时间
    */
    private Date createTime;
    /**
    * 更新人
    */
    private Long updateBy;
    /**
    * 更新时间
    */
    private Date updateTime;
    /**
    * 删除标志（0代表未删除，1代表已删除）
    */
    private Integer delFlag;
}
~~~~



### 3.1.7 实现

#### 3.1.7.1  数据库校验用户

从之前的分析我们可以知道，我们可以自定义一个UserDetailsService,让SpringSecurity使用我们的UserDetailsService。我们自己的UserDetailsService可以从数据库中查询用户名和密码。



##### 3.1.7.1.1  准备工作



​	我们先创建一个用户表， 建表语句如下：

~~~~mysql
CREATE TABLE `sys_user` (
  `id` BIGINT(20) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_name` VARCHAR(64) NOT NULL DEFAULT 'NULL' COMMENT '用户名',
  `nick_name` VARCHAR(64) NOT NULL DEFAULT 'NULL' COMMENT '昵称',
  `password` VARCHAR(64) NOT NULL DEFAULT 'NULL' COMMENT '密码',
  `status` CHAR(1) DEFAULT '0' COMMENT '账号状态（0正常 1停用）',
  `email` VARCHAR(64) DEFAULT NULL COMMENT '邮箱',
  `phonenumber` VARCHAR(32) DEFAULT NULL COMMENT '手机号',
  `sex` CHAR(1) DEFAULT NULL COMMENT '用户性别（0男，1女，2未知）',
  `avatar` VARCHAR(128) DEFAULT NULL COMMENT '头像',
  `user_type` CHAR(1) NOT NULL DEFAULT '1' COMMENT '用户类型（0管理员，1普通用户）',
  `create_by` BIGINT(20) DEFAULT NULL COMMENT '创建人的用户id',
  `create_time` DATETIME DEFAULT NULL COMMENT '创建时间',
  `update_by` BIGINT(20) DEFAULT NULL COMMENT '更新人',
  `update_time` DATETIME DEFAULT NULL COMMENT '更新时间',
  `del_flag` INT(11) DEFAULT '0' COMMENT '删除标志（0代表未删除，1代表已删除）',
  PRIMARY KEY (`id`)
) ENGINE=INNODB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COMMENT='用户表'
~~~~

​		引入MybatisPuls和mysql驱动的依赖

~~~~xml
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.4.3</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.2.8</version>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.32</version>
        </dependency>
~~~~

​	

​	配置数据库信息

~~~~yml
spring:
  datasource:
    druid:
      driver-class-name: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://localhost:3306/springsecurity?serverTimezone=Asia/Shanghai&useUnicode=true&characterEncoding=utf-8&zeroDateTimeBehavior=convertToNull&useSSL=false&allowPublicKeyRetrieval=true
      username: root
      password: root


mybatis-plus:
  configuration:
    map-underscore-to-camel-case: true
    #sql
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
  global-config:
    db-config:
      id-type: ASSIGN_ID
~~~~

​	



##### 3.1.7.1.2 核心代码实现

   定义UserDetailsService的实现类，我们上图中的第五步

```java
/**
 *   与数据库进行操作
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;


//   可以观看之前粉色的那张图片，这个方法是由DaoAuthenticationProvider调用
//   我们要在这方法中做的就是 想数据库中查询，获取用户信息、查询权限信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//      TODO 查询用户信息
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,username);

        User user = userMapper.selectOne(queryWrapper);
//      如果没有查询到用户，就抛出异常
        if(Objects.isNull(user)){
            throw new RuntimeException("用户或者密码错误");
        }

//      TODO 查询对应的权限信息（讲到授权后在补全这个地方）

//      TODO 封装成UserDetails将其返回

//      LoginUser是我们自己封装的一个UserDetails接口的实现类
        return new LoginUser(user);
    }
}
```





```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

    /**
     *
     * @return  获取权限信息
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//      返回权限信息的
        return null;
    }

    /**
     *   框架会调用LoginUser的getPassword方法获取当前用户的密码
     * @return   获取当前用户的密码
     */
    @Override
    public String getPassword() {

        return user.getPassword();
    }

    /**
     *
     * @return
     */
    @Override
    public String getUsername() {
        return user.getUserName();
    }

    /**
     * 判断是否没过期的
     *
     * @return false 代表超时
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否可用
     *
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```



注意：我们需要预先在数据库中添加数据。如果想让用户密码是铭文存储，则需要再密码前加{noop}



#### 3.1.7.2  密码加密存储

实际项目中我们不会把密码明文存储在数据库中。

​      默认使用的PasswordEncoder要求数据库中的密码格式为: {id}password ，它会根据id去判断密码的加密方式。但是我们一般不会采用这种方式。所以就需要***替换PasswordEncoder**。

​      我们一般**使用SpringSecurity为我们提供的BCryptPasswordEncoder**。

​       我们只需要使用把BCryptPasswordEncoder对象注入Spring容器中，Springsecurity就会使用该PasswordEncoder来进行密码校验。

​       我们可以**定义一个SpringSecurity的配置类，SpringSecurity要求这个配置类要继承WebSecurityConfigurerAdapter**,

​      当我们配置好下面的实体类后

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     *
     * @return 创建  BCryptPasswordEncoder 注入容器
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }
}
```



其中**PasswordEncoder**如下所示：

```java
@Autowired
private PasswordEncoder   passwordEncoder ;   //使用的时候这么注入就可以了，不用向下面那样创建
```



  **encode：**  传入一个密码的原文，就会帮我们加密。指的注意的是，即使我们的明文是一个样的，但生成的密文也有可能不一样。

```java
BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
String encode = bCryptPasswordEncoder.encode("1234");
System.out.println(encode);   //$2a$10$2z2HZ5ewLSyV9DqoyyHXB.4U8DVlPsfVQqgi61683XYEIQEJkL78y
```

  **matches：**进行密码校验的。传入一个想校验的密码（比如用户登录时输入的密码），再传入一个加密的密码(数据库存储的密码密文)。



   



![image-20230427180310562](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427180310562.png)





#### 3.1.7.3 自定义登录接口

按照我们之前“3.1.5 要解决的问题”中，自定义登录接口，调用ProviderManager的方法进行认证，如果认证通过生成jwt，把用户信息存入Redis中

自定义登录接口，让SpringSecurity对这个接口进行放行，让用户访问这个接口的时候不用登录也能访问。

```java
@Override   //这里不是Bean ，在public class SecurityConfig extends WebSecurityConfigurerAdapte类中
protected void configure(HttpSecurity http) throws Exception {
    http
            //关闭csrf
            .csrf().disable()
            //不通过Session获取SecurityContext
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            // 对于登录接口 允许匿名访问
            .antMatchers("/user/login").anonymous()
            // 除上面外的所有请求全部需要鉴权认证
            .anyRequest().authenticated();
}
```

在接口中我们通过AuthenticationManager的authenticate方法来进行用户认证，所以需要在SecurityConfig中配置把AuthenticationManager注入容器。如下面的第二个方法

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     *    密码加密解密
     * @return 创建  BCryptPasswordEncoder 注入容器
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    /**
     *
     * @return  在SecurityConfig中配置把AuthenticationManager注入容器。
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```



认证成功的话生成一个jwt，放入响应中放回。并且为了让用户下回请求时能通过jwt识别出具体哪个用户，我们需要把用户信息存入Redis，可以把用户id作为key

```java
@Service
public class LoginServiceImpl implements LoginService {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
//       TODO 通过AuthenticationManager的authenticate方法来进行用户认证
//          需要Authentication类型(接口)的参数,我们可以使用Authentication的实现类UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

//      TODO  如果认证没通过，给出对应的提示
        if (Objects.isNull(authenticate)) {
            throw new RuntimeException("登录失败");
        }

//      TODO 如果认证通过了，使用userId生成一个jwt，封装成ResponseResult对象进行返回
//          这个地方为什么能强转成LoginUser类型？
//           UserDetailsServiceImpl类实现了UserDetailsService并且重写了loadUserByUsername方法，其方法返回值是UserDetails
//           但是创建了一个类LoginUser实现了UserDetails接口
        LoginUser loginUser = (LoginUser)authenticate.getPrincipal();

        Long id = loginUser.getUser().getId();

        String jwt = JwtUtil.createJWT(id.toString());

//      希望date数据中是  key:value的形式，所以用个map
        Map<String,String> map = new HashMap<>();
        map.put("token",jwt);

//      TODO 把完整的用户信息存入Redis, userId作为key
        redisCache.setCacheObject("login:"+id,loginUser);


        return new ResponseResult<>(200,"登录成功",map);

    }
}
```



![image-20230427222246160](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230427222246160.png)



#### 3.1.7.4  铺垫知识 jwt工具类使用

```java
/**
 * JWT工具类
 */
public class JwtUtil {

    //有效期为
    public static final Long JWT_TTL = 60 * 60 *1000L;// 60 * 60 *1000  一个小时
    //设置秘钥明文
    public static final String JWT_KEY = "sangeng";

    public static String getUUID(){
        String token = UUID.randomUUID().toString().replaceAll("-", "");
        return token;
    }

    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @return
     */
    public static String createJWT(String subject) {
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID());// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public static String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID());// 设置过期时间
        return builder.compact();
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if(ttlMillis==null){
            ttlMillis=JwtUtil.JWT_TTL;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setId(uuid)              //唯一的ID
                .setSubject(subject)   // 主题  可以是JSON数据
                .setIssuer("sg")     // 签发者
                .setIssuedAt(now)      // 签发时间
                .signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                .setExpiration(expDate);
    }

    /**
     * 创建token
     * @param id
     * @param subject
     * @param ttlMillis
     * @return
     */
    public static String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id);// 设置过期时间
        return builder.compact();
    }

    public static void main(String[] args) throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJjYWM2ZDVhZi1mNjVlLTQ0MDAtYjcxMi0zYWEwOGIyOTIwYjQiLCJzdWIiOiJzZyIsImlzcyI6InNnIiwiaWF0IjoxNjM4MTA2NzEyLCJleHAiOjE2MzgxMTAzMTJ9.JVsSbkP94wuczb4QryQbAke3ysBDIL5ou8fWsbt_ebg";
        Claims claims = parseJWT(token);
        System.out.println(claims);
    }

    /**
     * 生成加密后的秘钥 secretKey
     * @return
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }

    /**
     * 解析
     *
     * @param jwt
     * @return
     * @throws Exception
     */
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }
}
```









#### 3.1.7.5  Jwt 认证过滤器代码实现

   根据之前的分析，在这里我们要实现

① 获取token

② 解析token获取其中的userid

③ 从Redis中获取用户信息

④ 存入SecurityContextHolder



```java
/**
 * 之前我们选择的是实现Filter接口，但是这个过滤器接口存在一点问题，有可能发一次请求经过好几次过滤器
 * OncePerRequestFilter  是过滤器的实现类，一次请求只经过一个过滤器
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//      TODO 获取token (前端发送请求携带过来)
        String token = request.getHeader("token");   //有可能是空的，不一定所有的请求都携带token
        if (!Strings.hasText(token)) {
//          说明token没有，直接放行
//          为什么放行？  因为后面的操作是对token的解析，而这个请求没有携带token
//                      除此之外，后面还有其他的过滤器，也可以在进行判断（比如说在FilterSecurityInterceptor中）
            filterChain.doFilter(request, response);
//          为什么加return？  放行后会执行到后面的几个过滤器，都执行完然后响应的时候还会执行一遍过滤器链
            return;
        }

//      TODO 解析token
        Claims claims = null;
        String userId =null;
        try {
            claims = JwtUtil.parseJWT(token);
//          这样获取的就是生成token的原来数据，因为当时我们使用userid生成的token
             userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }

//      TODO 从Redis中获取用户信息
        String redisKey = "login:"+userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (loginUser ==null ){
            throw new RuntimeException("token非法");
        }


//      TODO 将用户信息存入到SecurityContextHolder中
//      三个参数：在构造方法中会有一个super.setAuthenticated(true)，表示已认证的情况
//      第一个参数：用户信息，第二个参数：null,第三个参数：Collection集合，有关权限的信息，但是现在还没有权限信息，先写null
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginUser,null,null);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

//      TODO: 放行
        filterChain.doFilter(request, response);
    }
}
```



**虽然我们把这个过滤器链写好了，但是此过滤器并不会在SpringSecurity当中，并且要指定过滤器在过滤器链中的位置，我们需要自己进行配置**

```java
    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/user/login").anonymous()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();
//      添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
```





#### 3.1.7.6 退出登录

   用户之前生成的token不能使用了。

```java
    @Override
    public ResponseResult logout() {
//      TODO 获取SecurityContextHolder中的用户id
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long id = loginUser.getUser().getId();

//      TODO 删除Redis中的值
        redisCache.deleteObject("login:"+id);

        return new ResponseResult<>(200,"注销成功");
    }
```





##  3.2 授权

   微信来举例子，微信登录成功后用户即可使用微信的功能，比如，发红包、!发朋友圈、添加好友等，没有绑定银行卡的用户是无法发送红包的，绑定银行卡的用户才可以发红包，发红包功能、发朋友圈功能都是微信的资源即功能资源，用户拥有发红包功能的权限才可以正常使用发送红包功能，拥有发朋友圈功能的权限才可以使用发朋友圈功能，这个根据用户的权限来控制用户使用资源的过程就是授权。



**为什么要授权 ?**
   认证是为了保证用户身份的合法性，授权则是为了更细粒度的对隐私数据进行划分，授权是在认证通过后发生的，控制不同的用户能够访问不同的资源。

​    **授权:**授权是用户认证通过根据用户的权限来控制用户访问资源的过程，**拥有资源的访问权限则正常访问没有权限则拒绝访问。**



### 3.2.1 权限系统的作用

   	例如一个学校图书馆的管理系统，如果是普通学生登录就能看到借书还书相关的功能，不可能让他看到并且去使用添加书籍信息，删除书籍信息等功能。但是如果是一个图书馆管理员的账号登录了，应该就能看到并使用添加书籍信息，删除书籍信息等功能。

​	总结起来就是**不同的用户可以使用不同的功能**。这就是权限系统要去实现的效果。

​	我们不能只依赖前端去判断用户的权限来选择显示哪些菜单哪些按钮。因为如果只是这样，如果有人知道了对应功能的接口地址就可以不通过前端，直接去发送请求来实现相关功能操作。

​	所以我们还**需要在后台进行用户权限的判断，判断当前用户是否有相应的权限，必须具有所需权限才能进行相应的操作**。

​	



### 3.2.2 授权基本流程

   在SpringSecurity中，会使用默认的FilterSecurityInterceptor来进行权限校验。在FilterSecurityInterceptor中会从SecurityContextHolder获取其中的Authentication，然后获取其中的权限信息。当前用户是否拥有访问当前资源所需的权限。 

 我们之前的图：![image-20230426235249540](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230426235249540.png)





### 3.2.3 授权实现

#### 3.2.3.1 限制访问资源所需权限

我们选择基于注解对权限控制的方式：开启相关配置

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)  //开启注解的功能
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    ..................
}
```

此时可以使用对应的注解

```java
@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping("/hello")
//    会执行hasAuthority('test')方法，返回值类型是布尔类型，如果是true就可以访问这个请求
    @PreAuthorize("hasAuthority('test')")  //访问资源之前进行一个资源的认证，是否能够访问这个资源
    private String hello(){
        return "hello";
    }
}
```

 



#### 3.2.3.2 封装权限信息

##### 3.2.3.2.1 补充 UserDetailsServiceImpl implements UserDetailsService类授权

```java
/**
 *   与数据库进行操作
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;


//   可以观看之前粉色的那张图片，这个方法是由DaoAuthenticationProvider调用
//   我们要在这方法中做的就是 想数据库中查询，获取用户信息、查询权限信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//      TODO 查询用户信息
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,username);

        User user = userMapper.selectOne(queryWrapper);
//      如果没有查询到用户，就抛出异常
        if(Objects.isNull(user)){
            throw new RuntimeException("用户不存在");
        }

//      TODO 查询对应的权限信息（讲到授权后在补全这个地方）
//        这个地方我们先把权限信息写死
        List<String> list = new ArrayList<>(Arrays.asList("test","admin"));


//      TODO 封装成UserDetails将其返回
//      LoginUser是我们自己封装的一个UserDetails接口的实现类
        return new LoginUser(user,list);  //传入用户信息及权限集合，我们现在对LoginUser进行了修改
    }
}

```







##### 3.2.3.2.2 补充  LoginUser implements UserDetails 类 授权

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

//  存储权限信息
    private List<String>  permissions;

//  为什么什么这个成员变量？
//     如果每次请求都把权限字符串封装成下面的代码，比较耗时间，我们直接把他设置成成员变量
    @JSONField(serialize = false)  //这个属性不会序列化到我们的Redis中
    private  List<SimpleGrantedAuthority> authorities;

    public LoginUser(User user) {
        this.user = user;
    }

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    /**
     *
     * @return  获取权限信息
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//      为什么什么这个成员变量？
//        如果每次请求都把权限字符串封装成下面的代码，比较耗时间，我们直接把他设置成成员变量

//        把permissions集合的String类型权限封装成Collection<? extends GrantedAuthority>的实现类SimpleGrantedAuthority
        if(authorities !=null){
            return authorities;
        }
         authorities = permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
//      返回权限信息的
        return authorities;
    }

    /**
     *   框架会调用LoginUser的getPassword方法获取当前用户的密码
     * @return   获取当前用户的密码
     */
    @Override
    public String getPassword() {

        return user.getPassword();
    }

    /**
     *
     * @return
     */
    @Override
    public String getUsername() {
        return user.getUserName();
    }

    /**
     * 判断是否没过期的
     *
     * @return false 代表超时
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否可用
     *
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```





##### 3.2.3.2.3 补充 JwtAuthenticationTokenFilter extends OncePerRequestFilter 类 授权

```java
**
 * 之前我们选择的是实现Filter接口，但是这个过滤器接口存在一点问题，有可能发一次请求经过好几次过滤器
 * OncePerRequestFilter  是过滤器的实现类，一次请求只经过一个过滤器
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//      TODO 获取token (前端发送请求携带过来)
        String token = request.getHeader("token");   //有可能是空的，不一定所有的请求都携带token
        if (!Strings.hasText(token)) {
//          说明token没有，直接放行
//          为什么放行？  因为后面的操作是对token的解析，而这个请求没有携带token
//                      除此之外，后面还有其他的过滤器，也可以在进行判断（比如说在FilterSecurityInterceptor中）
            filterChain.doFilter(request, response);
//          为什么加return？  放行后会执行到后面的几个过滤器，都执行完然后响应的时候还会执行一遍过滤器链
            return;
        }

//      TODO 解析token
        Claims claims = null;
        String userId =null;
        try {
            claims = JwtUtil.parseJWT(token);
//          这样获取的就是生成token的原来数据，因为当时我们使用userid生成的token
             userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }

//      TODO 从Redis中获取用户信息
        String redisKey = "login:"+userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (loginUser ==null ){
            throw new RuntimeException("token非法");
        }


//      TODO 将用户信息存入到SecurityContextHolder中、获取权限信息封装到Authentication中
//      三个参数：在构造方法中会有一个super.setAuthenticated(true)，表示已认证的情况
//      第一个参数：用户信息，第二个参数：null,第三个参数：Collection集合，有关权限的信息，但是现在还没有权限信息，先写null
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginUser,null,loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

//      TODO: 放行
        filterChain.doFilter(request, response);
    }
}
```







#### 3.2.3.3 从数据库查询权限信息

​    刚刚我们用户的权限是从代码中写死的，我们现在要把用户对应的权限放入到数据库，然后查询获取对应权限



##### 3.2.3.3.1 RBAC权限模型

​    RBAC权限模型，基于角色的权限控制，这是目前最常被开发者使用也是相对易用、通用权限模型。

​      一个角色就是一个角色组，比如管理员角色有什么权限，普通用户有什么权限........，这样的话我们就给用户分配角色就可以了。



![image-20230428155043807](https://picture-typora-zhangjingqi.oss-cn-beijing.aliyuncs.com/image-20230428155043807.png)





##### 3.2.3.3.2  建立权限表与角色表

​     值得注意的是，用户可以有多个角色，可以使图书管理员，也可以是借阅人，角色表也对应了多个用户，即用户表和角色表是多对多的关系。



   用户表与角色表关联，角色表与权限表关联。

```sql
DROP TABLE IF EXISTS `sys_menu`;

CREATE TABLE `sys_menu` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `menu_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '菜单名',
  `path` varchar(200) DEFAULT NULL COMMENT '路由地址',
  `component` varchar(255) DEFAULT NULL COMMENT '组件路径',
  `visible` char(1) DEFAULT '0' COMMENT '菜单状态（0显示 1隐藏）',
  `status` char(1) DEFAULT '0' COMMENT '菜单状态（0正常 1停用）',
  `perms` varchar(100) DEFAULT NULL COMMENT '权限标识',
  `icon` varchar(100) DEFAULT '#' COMMENT '菜单图标',
  `create_by` bigint(20) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `update_by` bigint(20) DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `del_flag` int(11) DEFAULT '0' COMMENT '是否删除（0未删除 1已删除）',
  `remark` varchar(500) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COMMENT='菜单表';

/*Table structure for table `sys_role` */

DROP TABLE IF EXISTS `sys_role`;

CREATE TABLE `sys_role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  `role_key` varchar(100) DEFAULT NULL COMMENT '角色权限字符串',
  `status` char(1) DEFAULT '0' COMMENT '角色状态（0正常 1停用）',
  `del_flag` int(1) DEFAULT '0' COMMENT 'del_flag',
  `create_by` bigint(200) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `update_by` bigint(200) DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `remark` varchar(500) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COMMENT='角色表';

/*Table structure for table `sys_role_menu` */

DROP TABLE IF EXISTS `sys_role_menu`;

CREATE TABLE `sys_role_menu` (
  `role_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `menu_id` bigint(200) NOT NULL DEFAULT '0' COMMENT '菜单id',
  PRIMARY KEY (`role_id`,`menu_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

/*Table structure for table `sys_user` */

DROP TABLE IF EXISTS `sys_user`;

CREATE TABLE `sys_user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '用户名',
  `nick_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '昵称',
  `password` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '密码',
  `status` char(1) DEFAULT '0' COMMENT '账号状态（0正常 1停用）',
  `email` varchar(64) DEFAULT NULL COMMENT '邮箱',
  `phonenumber` varchar(32) DEFAULT NULL COMMENT '手机号',
  `sex` char(1) DEFAULT NULL COMMENT '用户性别（0男，1女，2未知）',
  `avatar` varchar(128) DEFAULT NULL COMMENT '头像',
  `user_type` char(1) NOT NULL DEFAULT '1' COMMENT '用户类型（0管理员，1普通用户）',
  `create_by` bigint(20) DEFAULT NULL COMMENT '创建人的用户id',
  `create_time` datetime DEFAULT NULL COMMENT '创建时间',
  `update_by` bigint(20) DEFAULT NULL COMMENT '更新人',
  `update_time` datetime DEFAULT NULL COMMENT '更新时间',
  `del_flag` int(11) DEFAULT '0' COMMENT '删除标志（0代表未删除，1代表已删除）',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

/*Table structure for table `sys_user_role` */

DROP TABLE IF EXISTS `sys_user_role`;

CREATE TABLE `sys_user_role` (
  `user_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '用户id',
  `role_id` bigint(200) NOT NULL DEFAULT '0' COMMENT '角色id',
  PRIMARY KEY (`user_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```



SELECT 
	DISTINCT m.`perms`
FROM
	sys_user_role ur
	LEFT JOIN `sys_role` r ON ur.`role_id` = r.`id`
	LEFT JOIN `sys_role_menu` rm ON ur.`role_id` = rm.`role_id`
	LEFT JOIN `sys_menu` m ON m.`id` = rm.`menu_id`
WHERE
	user_id = 2
	AND r.`status` = 0
	AND m.`status` = 0









##### 3.2.3.3.3 实体类

```java
/**
 * 菜单表(Menu)实体类
 */
@TableName(value="sys_menu")
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Menu implements Serializable {
    private static final long serialVersionUID = -54979041104113736L;
    
    @TableId
    private Long id;
    /**
    * 菜单名
    */
    private String menuName;
    /**
    * 路由地址
    */
    private String path;
    /**
    * 组件路径
    */
    private String component;
    /**
    * 菜单状态（0显示 1隐藏）
    */
    private String visible;
    /**
    * 菜单状态（0正常 1停用）
    */
    private String status;
    /**
    * 权限标识
    */
    private String perms;
    /**
    * 菜单图标
    */
    private String icon;
    
    private Long createBy;
    
    private Date createTime;
    
    private Long updateBy;
    
    private Date updateTime;
    /**
    * 是否删除（0未删除 1已删除）
    */
    private Integer delFlag;
    /**
    * 备注
    */
    private String remark;
}
```



```java
@Mapper
public interface MenuMapper extends BaseMapper<Menu> {
    @Select("SELECT \n" +
            "\tDISTINCT m.`perms`\n" +
            "FROM\n" +
            "\tsys_user_role ur\n" +
            "\tLEFT JOIN `sys_role` r ON ur.`role_id` = r.`id`\n" +
            "\tLEFT JOIN `sys_role_menu` rm ON ur.`role_id` = rm.`role_id`\n" +
            "\tLEFT JOIN `sys_menu` m ON m.`id` = rm.`menu_id`\n" +
            "WHERE\n" +
            "\tuser_id =  #{userId}\n" +
            "\tAND r.`status` = 0\n" +
            "\tAND m.`status` = 0")
    List<String>  selectPermsByUserId(Long userId);
}
```











#####   3.2.3.3.4   补充 UserDetailsServiceImpl implements UserDetailsService类授权方法



```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private MenuMapper menuMapper;

//   可以观看之前粉色的那张图片，这个方法是由DaoAuthenticationProvider调用
//   我们要在这方法中做的就是 想数据库中查询，获取用户信息、查询权限信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//      TODO 查询用户信息
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,username);

        User user = userMapper.selectOne(queryWrapper);
//      如果没有查询到用户，就抛出异常
        if(Objects.isNull(user)){
            throw new RuntimeException("用户不存在");
        }

//      TODO 查询对应的权限信息（讲到授权后在补全这个地方）
        List<String> list = menuMapper.selectPermsByUserId(user.getId());
//        List<String> list = new ArrayList<>(Arrays.asList("test","admin"));  //写死


//      TODO 封装成UserDetails将其返回
//      LoginUser是我们自己封装的一个UserDetails接口的实现类
        return new LoginUser(user,list);  //传入用户信息及权限集合
    }
}
```





```java
@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping("/hello")
//    会执行hasAuthority('test')方法，返回值类型是布尔类型，如果是true就可以访问这个请求
    @PreAuthorize("hasAuthority('system:dept:list')")  //访问资源之前进行一个资源的认证，是否能够访问这个资源
    private String hello(){
        return "hello";
    }
}
```











# 四、 自定义失败处理

​       希望在认证失败或者是授权失败的情况下也能和我们的接口一样返回相同结构的ison，这样可以让前端能对响

​    应进行统一的处理。要实现这个功能我们需要知道SpringSecurity的异常处理机制。



​        在SpringSecurity中，如果我们在认证或者授权的过程中出现了**异常会被ExceptionTranslationFilter捕获到**。**在ExceptionTranslationFilter中会去判断是认证失败还是授权失败出现的异常**。



​       如果是**认证过程**中出现的**异常**会被封装成**AuthenticationException然后调用AuthenticationEntrvPoint对象的方法去进行异常外理**



​     如果是**授权过程**中出现的**异常**会被封装成**AccessDeniedException然后调用AccessDeniedHandler对象的方法去进行异常处理**.



​     **所以如果我们需要自定义异常处理，我们只需要自定义AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity即可。**





## 4.1 自定义实现类





### 4.1.1 自定义AuthenticationEntryPoint 提示认证失败

```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseResult  r = new ResponseResult(HttpStatus.UNAUTHORIZED.value(),"用户认证失败。请重新登录");  //认证失败
        String json = JSON.toJSONString(r);
//      不论成功还是失败，都是JSON格式
        WebUtils.renderString(response,json);
    }
}
```





### 4.1.2  自定义AccessDeniedHandler   提示授权失败

```java
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseResult r = new ResponseResult(HttpStatus.FORBIDDEN.value(),"权限不足");  //认证失败
        String json = JSON.toJSONString(r);
//      不论成功还是失败，都是JSON格式
        WebUtils.renderString(response,json); // 封装的方法
    }
}
```





## 4.2 配置给SpringSecurity

​     **所以如果我们需要自定义异常处理，我们只需要自定义AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity即可。**



```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     *    密码加密解密
     * @return 创建  BCryptPasswordEncoder 注入容器
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }


    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Autowired
    private AuthenticationEntryPoint AuthenticationEntryPoint;

    @Autowired
    private AccessDeniedHandler AccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/user/login").anonymous()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();
//      TODO 添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

//      TODO 配置异常处理器
//      添加AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity
        http.exceptionHandling()
//              认证失败处理器
                .authenticationEntryPoint( AuthenticationEntryPoint)
//              授权失败处理器
                .accessDeniedHandler(AccessDeniedHandler);
    }

    /**
     *
     * @return  在SecurityConfig中配置把AuthenticationManager注入容器。
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```







# 五、跨域问题

浏览器出于安全的考虑，使用XMLHttpRequest对象发起http请求时必须遵守同源策略，否则就是跨域HTTP请求，默认情况下是被禁止的。**同源策略要求源相同才能正常进行通信，即协议、域名、端口号都完全一致。**

前后端分离项目，前端项目和后端项目一般都不是同源的，所以肯定会存在跨域请求问题。



## 5.1  SpringBoot 配置

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // 设置允许跨域的路径
        registry.addMapping("/**")
                // 设置允许跨域请求的域名
                .allowedOriginPatterns("*")
                // 是否允许cookie
                .allowCredentials(true)
                // 设置允许的请求方式
                .allowedMethods("GET", "POST", "DELETE", "PUT")
                // 设置允许的header属性
                .allowedHeaders("*")
                // 跨域允许时间
                .maxAge(3600);
    }
}
```







## 5.2 开启SpringSecurity跨域访问

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/user/login").anonymous()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();
//      TODO 添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

//      TODO 配置异常处理器
//      添加AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity
        http.exceptionHandling()
//              认证失败处理器
                .authenticationEntryPoint( AuthenticationEntryPoint)
//              授权失败处理器
                .accessDeniedHandler(AccessDeniedHandler);
//      TODO 允许跨域
        http.cors();
    }
```







# 六、遗留问题



## 6.1 其它权限校验方法



​	我们前面都是使用@PreAuthorize注解，然后在在其中使用的是hasAuthority方法进行校验。SpringSecurity还为我们提供了其它方法例如：hasAnyAuthority，hasRole，hasAnyRole等。

​    

​	这里我们先不急着去介绍这些方法，我们先去理解hasAuthority的原理，然后再去学习其他方法你就更容易理解，而不是死记硬背区别。并且我们也可以选择定义校验方法，实现我们自己的校验逻辑。

​	hasAuthority方法实际是执行到了SecurityExpressionRoot的hasAuthority，大家只要断点调试既可知道它内部的校验原理。

​	它内部其实是调用authentication的getAuthorities方法获取用户的权限列表。然后判断我们存入的方法参数数据在权限列表中。



​	hasAnyAuthority方法可以传入多个权限，只有用户有其中任意一个权限都可以访问对应资源。

~~~~java
    @PreAuthorize("hasAnyAuthority('admin','test','system:dept:list')")
    public String hello(){
        return "hello";
    }
~~~~



​	hasRole要求有对应的角色才可以访问，但是它内部会把我们传入的参数拼接上 **ROLE_** 后再去比较。所以这种情况下要用用户对应的权限也要有 **ROLE_** 这个前缀才可以。

~~~~java
    @PreAuthorize("hasRole('system:dept:list')")
    public String hello(){
        return "hello";
    }
~~~~



​	hasAnyRole 有任意的角色就可以访问。它内部也会把我们传入的参数拼接上 **ROLE_** 后再去比较。所以这种情况下要用用户对应的权限也要有 **ROLE_** 这个前缀才可以。

~~~~java
    @PreAuthorize("hasAnyRole('admin','system:dept:list')")
    public String hello(){
        return "hello";
    }
~~~~



## 6.2 自定义权限校验方法

​	我们也可以定义自己的权限校验方法，在@PreAuthorize注解中使用我们的方法。

~~~~java
@Component("ex")   //bean的名字为ex
public class SGExpressionRoot {

    public boolean hasAuthority(String authority){
        //获取当前用户的权限
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        List<String> permissions = loginUser.getPermissions();
        //判断用户权限集合中是否存在authority
        return permissions.contains(authority);
    }
}
~~~~

​	 在SPEL表达式中使用 @ex相当于获取容器中bean的名字未ex的对象。然后再调用这个对象的hasAuthority方法

~~~~java
    @RequestMapping("/hello")
    @PreAuthorize("@ex.hasAuthority('system:dept:list')")
    public String hello(){
        return "hello";
    }
~~~~





## 6.3 基于配置的权限控制



​	我们也可以在配置类中使用使用配置的方式对资源进行权限控制。

~~~~java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/user/login").anonymous()   //TODO 匿名访问，不需要验证
                .antMatchers("/testCors").hasAuthority("system:dept:list222")  //TODO  在这里进行配置的
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();

        //添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        //配置异常处理器
        http.exceptionHandling()
                //配置认证失败处理器
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        //允许跨域
        http.cors();
    }
~~~~



## 6.4 CSRF



​    CSRF是指跨站请求伪造（Cross-site request forgery），是web常见的攻击之一。

​	https://blog.csdn.net/freeking101/article/details/86537087

​	SpringSecurity去防止CSRF攻击的方式就是通过csrf_token。后端会生成一个csrf_token，前端发起请求的时候需要携带这个csrf_token,后端会有过滤器进行校验，如果没有携带或者是伪造的就不允许访问。

​	我们可以发现CSRF攻击依靠的是cookie中所携带的认证信息。但是在前后端分离的项目中我们的认证信息其实是token，而token并不是存储中cookie中，并且需要前端代码去把token设置到请求头中才可以，所以CSRF攻击也就不用担心了。



​	**前后端分离项目天然不怕CSRF攻击的，所以我们在最开始配置的时候是csrf().disable()**





## 6.5 认证成功处理器

​	实际上在UsernamePasswordAuthenticationFilter进行登录认证的时候，如果登录成功了是会调用AuthenticationSuccessHandler的方法进行认证成功后的处理的。AuthenticationSuccessHandler就是登录成功处理器。

​	我们也可以自己去自定义成功处理器进行成功后的相应处理。

~~~~java
@Component
public class SGSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("认证成功了");
    }
}

~~~~

~~~~java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().successHandler(successHandler);

        http.authorizeRequests().anyRequest().authenticated();
    }
}

~~~~









## 6.6 认证失败处理器

实际上在UsernamePasswordAuthenticationFilter进行登录认证的时候，如果认证失败了是会调用AuthenticationFailureHandler的方法进行认证失败后的处理的。AuthenticationFailureHandler就是登录失败处理器。

​	我们也可以自己去自定义失败处理器进行失败后的相应处理。

~~~~java
@Component
public class SGFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        System.out.println("认证失败了");
    }
}
~~~~



~~~~java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private AuthenticationFailureHandler failureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
//                配置认证成功处理器
                .successHandler(successHandler)
//                配置认证失败处理器
                .failureHandler(failureHandler);

        http.authorizeRequests().anyRequest().authenticated();
    }
}

~~~~









## 6.7 注销成功处理器



~~~~java
@Component
public class SGLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("注销成功");
    }
}

~~~~

~~~~java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private AuthenticationFailureHandler failureHandler;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
//                配置认证成功处理器
                .successHandler(successHandler)
//                配置认证失败处理器
                .failureHandler(failureHandler);

        http.logout()
                //配置注销成功处理器
                .logoutSuccessHandler(logoutSuccessHandler);

        http.authorizeRequests().anyRequest().authenticated();
    }
}
~~~~





























