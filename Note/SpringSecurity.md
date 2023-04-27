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





#### 3.1.7.3 登录接口









##  3.3 授权

   微信来举例子，微信登录成功后用户即可使用微信的功能，比如，发红包、!发朋友圈、添加好友等，没有绑定银行卡的用户是无法发送红包的，绑定银行卡的用户才可以发红包，发红包功能、发朋友圈功能都是微信的资源即功能资源，用户拥有发红包功能的权限才可以正常使用发送红包功能，拥有发朋友圈功能的权限才可以使用发朋友圈功能，这个根据用户的权限来控制用户使用资源的过程就是授权。

**为什么要授权 ?**
   认证是为了保证用户身份的合法性，授权则是为了更细粒度的对隐私数据进行划分，授权是在认证通过后发生的，控制不同的用户能够访问不同的资源。

​    **授权:**授权是用户认证通过根据用户的权限来控制用户访问资源的过程，**拥有资源的访问权限则正常访问没有权限则拒绝访问。**







