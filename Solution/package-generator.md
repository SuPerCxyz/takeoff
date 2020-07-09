创建目标目录，并删除目标目录下所有文件</br>
mkdir -p /data/release/solution-storage/ && rm -rf /data/release/solution-storage/*</br>
mkdir -p /data/release/solution-storage/scripts/ && rm -rf /data/release/solution-storage/scripts/*</br>
mkdir -p /data/release/solution-storage/rpms/ && rm -rf /data/release/solution-storage/rpms/*


将solution-storage项目下存储目录下文件和common文件复制到/data/release/solution-storage/scripts目录下</br>
cp -r /home/superc/EasyStack/solution_package/arm_test/solution-storage/test/* /data/release/solution-storage/scripts</br>
cp -r /home/superc/EasyStack/solution_package/arm_test/solution-storage/common/* /data/release/solution-storage/scripts</br>

/data/release/solution-storage文件夹内容如下：</br>
```shell
manifest.yaml  release-notes.txt  rpms  scripts
```

提取/data/release/solution-storage/scripts目录下manifest.yaml文件和release-notes.txt到上一层目录，后续做文件签名需要使用</br>
cp /data/release/solution-storage/scripts/manifest.yaml /data/release/solution-storage</br>
cp /data/release/solution-storage/scripts/release-notes.txt /data/release/solution-storage</br>


将存储目录rpms目录内rpm文件拷贝到/data/release/solution-storage/rpms目录下并删除scripts/rpms文件夹</br>
cd /data/release/solution-storage && mv scripts/rpms/* rpms/;rm -rf scripts/rpms;</br>


判断是否/data/release/solution-storage/rpms文件夹内是否存在文件，如果存在和压缩rpms文件夹为rpms.zip后删除rpm文件夹，不存在则直接删除rpms文件夹</br>
cd /data/release/solution-storage && if [ "`ls rpms`" = "" ]; then rm -rf rpms;else zip -r rpms.zip rpms/*; rm -rf rpms;fi</br>

/data/release/solution-storage文件夹内容如下：</br>
```shell
manifest.yaml  release-notes.txt  scripts.zip
```

压缩/data/release/solution-storage/scripts文件夹下所有内容生成scripts.zip后删除scripts文件夹</br>
cd /data/release/solution-storage/scripts && zip -r ../scripts.zip ./*;cd ../;rm -rf scripts</br>


对/data/release/solution-storage目录下文件做md5校验并保存到resource.md5文件内，
cd /data/release/solution-storage && find ./ ! -name resource.md5 -type f -exec md5sum {} \; | sort -k 2 > resource.md5

/data/release/solution-storage文件夹内容如下：</br>
```shell
manifest.yaml  release-notes.txt  resource.md5  scripts.zip
```

读取resource.md5文件内容和private.key内容后使用Crypto生成签名后写到signature.es文件</br>
签名代码
```python
def generate_signature(md5, private_key):
    rsakey = RSA.importKey(private_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(md5)
    sign = signer.sign(digest)
    signed_data = b64encode(sign)
    return signed_data
```

校验代码</br>
```python
def _verify_sign(cls, signature, resource_md5):
    with open(resource_md5, 'r') as md5:
        rsakey = RSA.importKey(b64decode(pub_key))
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(md5.read())
    return signer.verify(digest, signature)
```


删除resource.md5文件后打包文件</br>
cd /data/release/solution-storage && rm -f resource.md5</br>
cd /data/release/solution-storage && zip -P EasyStack20!8ECSRocks! -r solution-storage-test.es * </br>

/data/release/solution-storage文件夹内容如下：</br>
```shell
manifest.yaml  release-notes.txt  scripts.zip  signature.es  solution-storage-test.es
```


RSA公钥和私钥是什么？</br>
首先来说，RSA是一种非对称加密算法，它是由三位数学家（Rivest、Shamir、Adleman）设计出来的。非对称加密是相对于对称加密而言的。对称加密算法是指加密解密使用的是同一个秘钥，而非对称加密是由两个密钥（公钥、私钥）来进行加密解密的，由此可见非对称加密安全性更高。</br>
公钥顾名思义就是公开的密钥会发放给多个持有人，而私钥是私有密码往往只有一个持有人。</br>

##### 公私钥特性

&nbsp;&nbsp;公钥与私钥是成对出现的；</br>
&nbsp;&nbsp;私钥文件中包含了公钥数据，所以可以基于私钥导出公钥；</br>
&nbsp;&nbsp;密钥越长，越难破解，所以2048位密钥比1024位密钥要更安全；</br>
&nbsp;&nbsp;公钥和私钥都是密钥，被公开的那个就是公钥，没有被公开的那个就是私钥；</br>
&nbsp;&nbsp;公钥和私钥都可用于加密和解密。</br>

公钥和私钥都可以用于加解密操作，用公钥加密的数据只能由对应的私钥解密，反之亦然。虽说两者都可用于加密，但是不同场景使用不同的密钥来加密，规则如下：

1、私钥用于签名、公钥用于验签：</br>
签名和加密作用不同，签名并不是为了保密，而是为了保证这个签名是由特定的某个人签名的，而不是被其它人伪造的签名，所以私钥的私有性就适合用在签名用途上。</br>
私钥签名后，只能由对应的公钥解密，公钥又是公开的（很多人可持有），所以这些人拿着公钥来解密，解密成功后就能判断出是持有私钥的人做的签名，验证了身份合法性。</br>

2、公钥用于加密、私钥用于解密，这才能起到加密作用：</br>
因为公钥是公开的，很多人可以持有公钥。若用私钥加密，那所有持有公钥的人都可以进行解密，这是不安全的！
若用公钥加密，那只能由私钥解密，而私钥是私有不公开的，只能由特定的私钥持有人解密，保证的数据的安全性。</br>
