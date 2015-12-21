function range(s1,s2) {
    var arr = [];
   for (var i = 0; i <= (s2-s1); i++) {
    arr.push(i);
   }
   return arr;
}

function authcode(string, operation, key) {
	// 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
	// 加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
	// 取值越大，密文变动规律越大，密文变化 = 16 的 $ckey_length 次方
	
	var ckey_length = 4;
	
	// 密匙
	// $GLOBALS['discuz_auth_key'] 这里可以根据自己的需要修改
	//$key = md5($key ? $key : $GLOBALS['discuz_auth_key']); 
	key = hex_md5(key); 
	
	// 密匙a会参与加解密
	keya = hex_md5(key.substr(0, 16));
	// 密匙b会用来做数据完整性验证
	keyb = hex_md5(key.substr(16, 16));
	// 密匙c用于变化生成的密文
	keyc =  hex_md5(Date.parse(new Date())).substr(-ckey_length);
	
	/*if($operation == 'DECODE') {
	    $keyc = substr($string, 0, $ckey_length);
	}*/
	
	// 参与运算的密匙
	var cryptkey = keya+hex_md5(keya+keyc);
	var key_length = cryptkey.length;
	// 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)，解密时会通过这个密匙验证数据完整性
	// 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确
	
	
	string = '0000000000'+hex_md5(string+keyb).substr(0, 16)+string;
	
	
	string_length = string.length;
	var result = '';
	var box = range(0, 255);
	
	/*$rndkey = array();
	// 产生密匙簿
	for($i = 0; $i <= 255; $i++) {
	    $rndkey[$i] = ord($cryptkey[$i % $key_length]);
	}
	// 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上并不会增加密文的强度
	for($j = $i = 0; $i < 256; $i++) {
	    $j = ($j + $box[$i] + $rndkey[$i]) % 256;
	    $tmp = $box[$i];
	    $box[$i] = $box[$j];
	    $box[$j] = $tmp;
	}*/
	// 核心加解密部分
	var a = 0,
	    j = 0;
	for(i = 0; i < string_length; i++) {
	    a = (a + 1) % 256;
	    j = (j + box[a]) % 256;
	    tmp = box[a];
	    box[a] = box[j];
	    box[j] = tmp;
	    // 从密匙簿得出密匙进行异或，再转成字符
	    result += String.fromCharCode((string[i]).charCodeAt() ^ (box[(box[a] + box[j]) % 256]));
	
	}
	
	    // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
	    // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
	return keyc+base64_encode(result).replace(/=/g, '');

}

function jm(token,model,date) {
	var code3 = model+'|hijkappnbtv2015abcd|'+date;
	return authcode(token, "ENCODE", code3);
}
