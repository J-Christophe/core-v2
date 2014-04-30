/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/**
*
*  Base64 encode / decode
*  http://www.webtoolkit.info/
*
**/
 
var Base64 = {
 
	// private property
	_keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
 
	// public method for encoding
	encode : function (input) {
		var output = "";
		var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
		var i = 0;
 
		input = Base64._utf8_encode(input);
 
		while (i < input.length) {
 
			chr1 = input.charCodeAt(i++);
			chr2 = input.charCodeAt(i++);
			chr3 = input.charCodeAt(i++);
 
			enc1 = chr1 >> 2;
			enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
			enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
			enc4 = chr3 & 63;
 
			if (isNaN(chr2)) {
				enc3 = enc4 = 64;
			} else if (isNaN(chr3)) {
				enc4 = 64;
			}
 
			output = output +
			this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
			this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
 
		}
 
		return output;
	},
 
	// public method for decoding
	decode : function (input) {
		var output = "";
		var chr1, chr2, chr3;
		var enc1, enc2, enc3, enc4;
		var i = 0;
 
		input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
 
		while (i < input.length) {
 
			enc1 = this._keyStr.indexOf(input.charAt(i++));
			enc2 = this._keyStr.indexOf(input.charAt(i++));
			enc3 = this._keyStr.indexOf(input.charAt(i++));
			enc4 = this._keyStr.indexOf(input.charAt(i++));
 
			chr1 = (enc1 << 2) | (enc2 >> 4);
			chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
			chr3 = ((enc3 & 3) << 6) | enc4;
 
			output = output + String.fromCharCode(chr1);
 
			if (enc3 != 64) {
				output = output + String.fromCharCode(chr2);
			}
			if (enc4 != 64) {
				output = output + String.fromCharCode(chr3);
			}
 
		}
 
		output = Base64._utf8_decode(output);
 
		return output;
 
	},
 
	// private method for UTF-8 encoding
	_utf8_encode : function (string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	},
 
	// private method for UTF-8 decoding
	_utf8_decode : function (utftext) {
		var string = "";
		var i = 0;
		var c = c1 = c2 = 0;
 
		while ( i < utftext.length ) {
 
			c = utftext.charCodeAt(i);
 
			if (c < 128) {
				string += String.fromCharCode(c);
				i++;
			}
			else if((c > 191) && (c < 224)) {
				c2 = utftext.charCodeAt(i+1);
				string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
				i += 2;
			}
			else {
				c2 = utftext.charCodeAt(i+1);
				c3 = utftext.charCodeAt(i+2);
				string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
				i += 3;
			}
 
		}
 
		return string;
	}
};
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*
 *  md5.js 1.0b 27/06/96
 *
 * Javascript implementation of the RSA Data Security, Inc. MD5
 * Message-Digest Algorithm.
 *
 * Copyright (c) 1996 Henri Torgemane. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.
 *
 *
 * Modified with german comments and some information about collisions.
 * (Ralf Mieke, ralf@miekenet.de, http://mieke.home.pages.de)
 * French translation: Serge François, serge@selfhtml.org, http://fr.selfhtml.org
 */



function array(n) {
  for(i=0;i<n;i++) this[i]=0;
  this.length=n;
}



/* Quelques fonctions fondamentales doivent être transformées à cause
 * d'erreurs Javascript.
 * Essayez par exemple de calculer 0xffffffff >> 4 ...
 * Les fonctions utilisées maintenant sont il est vrai plus lentes que les
 * fonctions originales mais elles fonctionnent.
 */

function integer(n) { return n%(0xffffffff+1); }

function shr(a,b) {
  a=integer(a);
  b=integer(b);
  if (a-0x80000000>=0) {
    a=a%0x80000000;
    a>>=b;
    a+=0x40000000>>(b-1);
  } else
    a>>=b;
  return a;
}

function shl1(a) {
  a=a%0x80000000;
  if (a&0x40000000==0x40000000)
  {
    a-=0x40000000;
    a*=2;
    a+=0x80000000;
  } else
    a*=2;
  return a;
}

function shl(a,b) {
  a=integer(a);
  b=integer(b);
  for (var i=0;i<b;i++) a=shl1(a);
  return a;
}

function and(a,b) {
  a=integer(a);
  b=integer(b);
  var t1=(a-0x80000000);
  var t2=(b-0x80000000);
  if (t1>=0)
    if (t2>=0)
      return ((t1&t2)+0x80000000);
    else
      return (t1&b);
  else
    if (t2>=0)
      return (a&t2);
    else
      return (a&b);
}

function or(a,b) {
  a=integer(a);
  b=integer(b);
  var t1=(a-0x80000000);
  var t2=(b-0x80000000);
  if (t1>=0)
    if (t2>=0)
      return ((t1|t2)+0x80000000);
    else
      return ((t1|b)+0x80000000);
  else
    if (t2>=0)
      return ((a|t2)+0x80000000);
    else
      return (a|b);
}

function xor(a,b) {
  a=integer(a);
  b=integer(b);
  var t1=(a-0x80000000);
  var t2=(b-0x80000000);
  if (t1>=0)
    if (t2>=0)
      return (t1^t2);
    else
      return ((t1^b)+0x80000000);
  else
    if (t2>=0)
      return ((a^t2)+0x80000000);
    else
      return (a^b);
}

function not(a) {
  a=integer(a);
  return (0xffffffff-a);
}

/* Début de l'algorithme */

    var state = new array(4);
    var count = new array(2);
        count[0] = 0;
        count[1] = 0;
    var buffer = new array(64);
    var transformBuffer = new array(16);
    var digestBits = new array(16);

    var S11 = 7;
    var S12 = 12;
    var S13 = 17;
    var S14 = 22;
    var S21 = 5;
    var S22 = 9;
    var S23 = 14;
    var S24 = 20;
    var S31 = 4;
    var S32 = 11;
    var S33 = 16;
    var S34 = 23;
    var S41 = 6;
    var S42 = 10;
    var S43 = 15;
    var S44 = 21;

    function F(x,y,z) {
        return or(and(x,y),and(not(x),z));
    }

    function G(x,y,z) {
        return or(and(x,z),and(y,not(z)));
    }

    function H(x,y,z) {
        return xor(xor(x,y),z);
    }

    function I(x,y,z) {
        return xor(y ,or(x , not(z)));
    }

    function rotateLeft(a,n) {
        return or(shl(a, n),(shr(a,(32 - n))));
    }

    function FF(a,b,c,d,x,s,ac) {
        a = a+F(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a = a+b;
        return a;
    }

    function GG(a,b,c,d,x,s,ac) {
        a = a+G(b, c, d) +x + ac;
        a = rotateLeft(a, s);
        a = a+b;
        return a;
    }

    function HH(a,b,c,d,x,s,ac) {
        a = a+H(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a = a+b;
        return a;
    }

    function II(a,b,c,d,x,s,ac) {
        a = a+I(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a = a+b;
        return a;
    }

    function transform(buf,offset) {
        var a=0, b=0, c=0, d=0;
        var x = transformBuffer;

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];

        for (i = 0; i < 16; i++) {
            x[i] = and(buf[i*4+offset],0xff);
            for (j = 1; j < 4; j++) {
                x[i]+=shl(and(buf[i*4+j+offset] ,0xff), j * 8);
            }
        }

        /* tour 1 */
        a = FF ( a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
        d = FF ( d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
        c = FF ( c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
        b = FF ( b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
        a = FF ( a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
        d = FF ( d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
        c = FF ( c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
        b = FF ( b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
        a = FF ( a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
        d = FF ( d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
        c = FF ( c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
        b = FF ( b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
        a = FF ( a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
        d = FF ( d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
        c = FF ( c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
        b = FF ( b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

        /* tour 2 */
        a = GG ( a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
        d = GG ( d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
        c = GG ( c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
        b = GG ( b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
        a = GG ( a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
        d = GG ( d, a, b, c, x[10], S22,  0x2441453); /* 22 */
        c = GG ( c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
        b = GG ( b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
        a = GG ( a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
        d = GG ( d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
        c = GG ( c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
        b = GG ( b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
        a = GG ( a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
        d = GG ( d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
        c = GG ( c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
        b = GG ( b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

        /* tour 3 */
        a = HH ( a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
        d = HH ( d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
        c = HH ( c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
        b = HH ( b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
        a = HH ( a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
        d = HH ( d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
        c = HH ( c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
        b = HH ( b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
        a = HH ( a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
        d = HH ( d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
        c = HH ( c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
        b = HH ( b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
        a = HH ( a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
        d = HH ( d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
        c = HH ( c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
        b = HH ( b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

        /* tour 4 */
        a = II ( a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
        d = II ( d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
        c = II ( c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
        b = II ( b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
        a = II ( a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
        d = II ( d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
        c = II ( c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
        b = II ( b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
        a = II ( a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
        d = II ( d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
        c = II ( c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
        b = II ( b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
        a = II ( a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
        d = II ( d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
        c = II ( c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
        b = II ( b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

        state[0] +=a;
        state[1] +=b;
        state[2] +=c;
        state[3] +=d;

    }
    /* Avec l'initialisation de  Dobbertin:
       state[0] = 0x12ac2375;
       state[1] = 0x3b341042;
       state[2] = 0x5f62b97c;
       state[3] = 0x4ba763ed;
       s'il y a une collision:

       begin 644 Message1
       M7MH=JO6_>MG!X?!51$)W,CXV!A"=(!AR71,<X`Y-IIT9^Z&8L$2N'Y*Y:R.;
       39GIK9>TF$W()/MEHR%C4:G1R:Q"=
       `
       end

       begin 644 Message2
       M7MH=JO6_>MG!X?!51$)W,CXV!A"=(!AR71,<X`Y-IIT9^Z&8L$2N'Y*Y:R.;
       39GIK9>TF$W()/MEHREC4:G1R:Q"=
       `
       end
    */
    function init() {
        count[0]=count[1] = 0;
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        for (i = 0; i < digestBits.length; i++)
            digestBits[i] = 0;
    }

    function update(b) {
        var index,i;

        index = and(shr(count[0],3) , 0x3f);
        if (count[0]<0xffffffff-7)
          count[0] += 8;
        else {
          count[1]++;
          count[0]-=0xffffffff+1;
          count[0]+=8;
        }
        buffer[index] = and(b,0xff);
        if (index  >= 63) {
            transform(buffer, 0);
        }
    }

    function finish() {
        var bits = new array(8);
        var        padding;
        var        i=0, index=0, padLen=0;

        for (i = 0; i < 4; i++) {
            bits[i] = and(shr(count[0],(i * 8)), 0xff);
        }
        for (i = 0; i < 4; i++) {
            bits[i+4]=and(shr(count[1],(i * 8)), 0xff);
        }
        index = and(shr(count[0], 3) ,0x3f);
        padLen = (index < 56) ? (56 - index) : (120 - index);
        padding = new array(64);
        padding[0] = 0x80;
        for (i=0;i<padLen;i++)
          update(padding[i]);
        for (i=0;i<8;i++)
          update(bits[i]);

        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                digestBits[i*4+j] = and(shr(state[i], (j * 8)) , 0xff);
            }
        }
    }

/* Fin de l'algorithme MD5 */

function hexa(n) {
 var hexa_h = "0123456789abcdef";
 var hexa_c="";
 var hexa_m=n;
 for (hexa_i=0;hexa_i<8;hexa_i++) {
   hexa_c=hexa_h.charAt(Math.abs(hexa_m)%16)+hexa_c;
   hexa_m=Math.floor(hexa_m/16);
 }
 return hexa_c;
}


var ascii="01234567890123456789012345678901" +
          " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
          "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

function MD5(message)
{
 var l,s,k,ka,kb,kc,kd;

 init();
 for (k=0;k<message.length;k++) {
   l=message.charAt(k);
   update(ascii.lastIndexOf(l));
 }
 finish();
 ka=kb=kc=kd=0;
 for (i=0;i<4;i++) ka+=shl(digestBits[15-i], (i*8));
 for (i=4;i<8;i++) kb+=shl(digestBits[15-i], ((i-4)*8));
 for (i=8;i<12;i++) kc+=shl(digestBits[15-i], ((i-8)*8));
 for (i=12;i<16;i++) kd+=shl(digestBits[15-i], ((i-12)*8));
 s=hexa(kd)+hexa(kc)+hexa(kb)+hexa(ka);
 return s;
}
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
function Digest (config) {
	this.url = config.url;
	this.usr = config.usr;
	this.pwd = config.pwd;
	this.realm = config.realm;
	this.algorithm = config.algorithm;
	this.nonce = config.nonce;
	this.method = config.method;
	this.mode = config.mode;
	this.A1 = config.A1;
	
 	this.getDigestAuth = function () {
		this.resetHeaders();
		return this.buildAuthenticationRequest();
	};
	this.getA1 = function () {
		this.resetHeaders();
		return this.digest(this.usr + ':' + this.realm + ':' + this.pwd);
	};

	this.resetHeaders = function () {
		if ( typeof( this.headers) != "undefined" ) {
		  delete this.headers;
		}
		this.headers = {
		  'uri' : this.url,
		  'username' : this.usr,
		  'algorithm' : this.algorithm,
		  'realm' : this.realm, 
		  'nonce' : this.nonce
		};
	}; 

	this.digest = function (s) {
// Fallback to MD5 if requested algorithm is unavilable.
		if (typeof ( window[this.headers.algorithm] ) != 'function') {
		    if (typeof ( window['MD5'] ) != 'function') {
		      	alert('Votre navigateur ne supporte pas l\'authentification HTTP Digest !');
		      	return false;
		    } else {
		      	return MD5(s);
		    }
  		}
  		return window[this.headers.algorithm](s);
	};  

	this.buildResponseHash = function () {
		if (this.headers.salt) {
			auth.secret = auth.secret + ':' + auth.headers.salt;
		    delete auth.headers.salt;
		}
		if (this.headers.migrate) {
			auth.secret = this.digest(auth.secret);
		}
		
		var A1;
		if (Ext.isEmpty(this.A1)){
			A1 = this.getA1();
		}
		else {
			A1 = this.A1;
		}
		//delete this.secret;
		var A2 = this.digest(this.method + ':' + this.headers.uri);
		
		if (this.mode == 'digest') {
			return this.digest(A1 + ":" + this.headers.nonce + ":" + A2);
		}
		//TODO : voir s'il y a d'autres encodages possibles
		return null;
	};  

	this.buildAuthenticationRequest = function () {
	    var request = "Digest";
	    
	    var comma = ' ';
	    for (name in this.headers) {
	      request += comma + name + '="' + this.headers[name] + '"';
	      comma = ',';
	    }
	//    request += ' username="'+ auth.headers.username+ '"';
	    
	    // don't continue further if there is no algorithm yet.
	    if (typeof( this.headers.algorithm ) == 'undefined') {
	      return request;
	    }
	    
	    var r = this.buildResponseHash();
	    
	    if (r) {
	      request += ", response=\"" + r + "\"";
	      return request;
	    }
	
	    return false;
	};
  
};
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/**
 * shortcut for console.assert(object is not null neither undefined neither
 * empty string)
 */
/*global cerr,ctrace,isFirebugConsoleIsActive,console */
function ann(obj, message) {

    if (obj === true || obj === false) {
    	return; 
    }
    if (obj === undefined) {
        cerr('Object is undefined - ' + message);
        ctrace();
        return;
    }
    if (obj === null) {
        cerr('Object is null - ' + message);
        ctrace();
        return;
    }
    if (obj === "") {
        cerr('String seems empty - ' + message);
        ctrace();
        return;   
    }

    if (obj == NaN) {
        cerr('Object equals NaN - ' + message);
        ctrace();
        return;
    }

}


/**
 * shortcut for console.assert(object is not null neither undefined neither
 * empty string)
 */
function assert(condition, message) {

    if (!condition) {
    	cerr('Condition is not valid : ' + message);
    	ctrace();
    	return;
    }
}

/**
 * Log on the console
 */
function clog(message) {
	if (isFirebugConsoleIsActive()) {
		console.log(message);
	}	
}

/**
 * Display an error on the console
 */
function cerr(message) {
	if (isFirebugConsoleIsActive()) {
		console.trace();
	}	
}

/**
 * Trace the Javascript stack to this point
 */
function ctrace() {
	if (isFirebugConsoleIsActive()) {
		console.trace();
	}
}

/**
 * Trace the Javascript stack to this point
 */
function cdir(obj) {
	if (isFirebugConsoleIsActive()) {
		console.dir(obj);
	}
}

/**
 * Return true if the firebug console is active, false elsewhere
 */
function isFirebugConsoleIsActive() {
	try {
		if (console !== null && console !== undefined)
		{
			return true;
		} else {
			return false;
		}
	}
	catch (e) {
		return false;
	}
}




/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*
 * Ext JS Library 3.2.1
 * Copyright(c) 2006-2010 Ext JS, Inc.
 * licensing@extjs.com
 * http://www.extjs.com/license
 */
/**
 * @class Ext.ux.StatusBar
 * <p>Basic status bar component that can be used as the bottom toolbar of any {@link Ext.Panel}.  In addition to
 * supporting the standard {@link Ext.Toolbar} interface for adding buttons, menus and other items, the StatusBar
 * provides a greedy status element that can be aligned to either side and has convenient methods for setting the
 * status text and icon.  You can also indicate that something is processing using the {@link #showBusy} method.</p>
 * <pre><code>
new Ext.Panel({
    title: 'StatusBar',
    // etc.
    bbar: new Ext.ux.StatusBar({
        id: 'my-status',

        // defaults to use when the status is cleared:
        defaultText: 'Default status text',
        defaultIconCls: 'default-icon',

        // values to set initially:
        text: 'Ready',
        iconCls: 'ready-icon',

        // any standard Toolbar items:
        items: [{
            text: 'A Button'
        }, '-', 'Plain Text']
    })
});

// Update the status bar later in code:
var sb = Ext.getCmp('my-status');
sb.setStatus({
    text: 'OK',
    iconCls: 'ok-icon',
    clear: true // auto-clear after a set interval
});

// Set the status bar to show that something is processing:
sb.showBusy();

// processing....

sb.clearStatus(); // once completeed
</code></pre>
 * @extends Ext.Toolbar
 * @constructor
 * Creates a new StatusBar
 * @param {Object/Array} config A config object
 */
Ext.ux.StatusBar = Ext.extend(Ext.Toolbar, {
    /**
     * @cfg {String} statusAlign
     * The alignment of the status element within the overall StatusBar layout.  When the StatusBar is rendered,
     * it creates an internal div containing the status text and icon.  Any additional Toolbar items added in the
     * StatusBar's {@link #items} config, or added via {@link #add} or any of the supported add* methods, will be
     * rendered, in added order, to the opposite side.  The status element is greedy, so it will automatically
     * expand to take up all sapce left over by any other items.  Example usage:
     * <pre><code>
// Create a left-aligned status bar containing a button,
// separator and text item that will be right-aligned (default):
new Ext.Panel({
    title: 'StatusBar',
    // etc.
    bbar: new Ext.ux.StatusBar({
        defaultText: 'Default status text',
        id: 'status-id',
        items: [{
            text: 'A Button'
        }, '-', 'Plain Text']
    })
});

// By adding the statusAlign config, this will create the
// exact same toolbar, except the status and toolbar item
// layout will be reversed from the previous example:
new Ext.Panel({
    title: 'StatusBar',
    // etc.
    bbar: new Ext.ux.StatusBar({
        defaultText: 'Default status text',
        id: 'status-id',
        statusAlign: 'right',
        items: [{
            text: 'A Button'
        }, '-', 'Plain Text']
    })
});
</code></pre>
     */
    /**
     * @cfg {String} defaultText
     * The default {@link #text} value.  This will be used anytime the status bar is cleared with the
     * <tt>useDefaults:true</tt> option (defaults to '').
     */
    /**
     * @cfg {String} defaultIconCls
     * The default {@link #iconCls} value (see the iconCls docs for additional details about customizing the icon).
     * This will be used anytime the status bar is cleared with the <tt>useDefaults:true</tt> option (defaults to '').
     */
    /**
     * @cfg {String} text
     * A string that will be <b>initially</b> set as the status message.  This string
     * will be set as innerHTML (html tags are accepted) for the toolbar item.
     * If not specified, the value set for <code>{@link #defaultText}</code>
     * will be used.
     */
    /**
     * @cfg {String} iconCls
     * A CSS class that will be <b>initially</b> set as the status bar icon and is
     * expected to provide a background image (defaults to '').
     * Example usage:<pre><code>
// Example CSS rule:
.x-statusbar .x-status-custom {
    padding-left: 25px;
    background: transparent url(images/custom-icon.gif) no-repeat 3px 2px;
}

// Setting a default icon:
var sb = new Ext.ux.StatusBar({
    defaultIconCls: 'x-status-custom'
});

// Changing the icon:
sb.setStatus({
    text: 'New status',
    iconCls: 'x-status-custom'
});
</code></pre>
     */

    /**
     * @cfg {String} cls
     * The base class applied to the containing element for this component on render (defaults to 'x-statusbar')
     */
    cls : 'x-statusbar',
    /**
     * @cfg {String} busyIconCls
     * The default <code>{@link #iconCls}</code> applied when calling
     * <code>{@link #showBusy}</code> (defaults to <tt>'x-status-busy'</tt>).
     * It can be overridden at any time by passing the <code>iconCls</code>
     * argument into <code>{@link #showBusy}</code>.
     */
    busyIconCls : 'x-status-busy',
    /**
     * @cfg {String} busyText
     * The default <code>{@link #text}</code> applied when calling
     * <code>{@link #showBusy}</code> (defaults to <tt>'Loading...'</tt>).
     * It can be overridden at any time by passing the <code>text</code>
     * argument into <code>{@link #showBusy}</code>.
     */
    busyText : 'Loading...',
    /**
     * @cfg {Number} autoClear
     * The number of milliseconds to wait after setting the status via
     * <code>{@link #setStatus}</code> before automatically clearing the status
     * text and icon (defaults to <tt>5000</tt>).  Note that this only applies
     * when passing the <tt>clear</tt> argument to <code>{@link #setStatus}</code>
     * since that is the only way to defer clearing the status.  This can
     * be overridden by specifying a different <tt>wait</tt> value in
     * <code>{@link #setStatus}</code>. Calls to <code>{@link #clearStatus}</code>
     * always clear the status bar immediately and ignore this value.
     */
    autoClear : 5000,

    /**
     * @cfg {String} emptyText
     * The text string to use if no text has been set.  Defaults to
     * <tt>'&nbsp;'</tt>).  If there are no other items in the toolbar using
     * an empty string (<tt>''</tt>) for this value would end up in the toolbar
     * height collapsing since the empty string will not maintain the toolbar
     * height.  Use <tt>''</tt> if the toolbar should collapse in height
     * vertically when no text is specified and there are no other items in
     * the toolbar.
     */
    emptyText : '&nbsp;',

    // private
    activeThreadId : 0,

    // private
    initComponent : function(){
        if(this.statusAlign=='right'){
            this.cls += ' x-status-right';
        }
        Ext.ux.StatusBar.superclass.initComponent.call(this);
    },

    // private
    afterRender : function(){
        Ext.ux.StatusBar.superclass.afterRender.call(this);

        var right = this.statusAlign == 'right';
        this.currIconCls = this.iconCls || this.defaultIconCls;
        this.statusEl = new Ext.Toolbar.TextItem({
            cls: 'x-status-text ' + (this.currIconCls || ''),
            text: this.text || this.defaultText || ''
        });

        if(right){
            this.add('->');
            this.add(this.statusEl);
        }else{
            this.insert(0, this.statusEl);
            this.insert(1, '->');
        }
        this.doLayout();
    },

    /**
     * Sets the status {@link #text} and/or {@link #iconCls}. Also supports automatically clearing the
     * status that was set after a specified interval.
     * @param {Object/String} config A config object specifying what status to set, or a string assumed
     * to be the status text (and all other options are defaulted as explained below). A config
     * object containing any or all of the following properties can be passed:<ul>
     * <li><tt>text</tt> {String} : (optional) The status text to display.  If not specified, any current
     * status text will remain unchanged.</li>
     * <li><tt>iconCls</tt> {String} : (optional) The CSS class used to customize the status icon (see
     * {@link #iconCls} for details). If not specified, any current iconCls will remain unchanged.</li>
     * <li><tt>clear</tt> {Boolean/Number/Object} : (optional) Allows you to set an internal callback that will
     * automatically clear the status text and iconCls after a specified amount of time has passed. If clear is not
     * specified, the new status will not be auto-cleared and will stay until updated again or cleared using
     * {@link #clearStatus}. If <tt>true</tt> is passed, the status will be cleared using {@link #autoClear},
     * {@link #defaultText} and {@link #defaultIconCls} via a fade out animation. If a numeric value is passed,
     * it will be used as the callback interval (in milliseconds), overriding the {@link #autoClear} value.
     * All other options will be defaulted as with the boolean option.  To customize any other options,
     * you can pass an object in the format:<ul>
     *    <li><tt>wait</tt> {Number} : (optional) The number of milliseconds to wait before clearing
     *    (defaults to {@link #autoClear}).</li>
     *    <li><tt>anim</tt> {Number} : (optional) False to clear the status immediately once the callback
     *    executes (defaults to true which fades the status out).</li>
     *    <li><tt>useDefaults</tt> {Number} : (optional) False to completely clear the status text and iconCls
     *    (defaults to true which uses {@link #defaultText} and {@link #defaultIconCls}).</li>
     * </ul></li></ul>
     * Example usage:<pre><code>
// Simple call to update the text
statusBar.setStatus('New status');

// Set the status and icon, auto-clearing with default options:
statusBar.setStatus({
    text: 'New status',
    iconCls: 'x-status-custom',
    clear: true
});

// Auto-clear with custom options:
statusBar.setStatus({
    text: 'New status',
    iconCls: 'x-status-custom',
    clear: {
        wait: 8000,
        anim: false,
        useDefaults: false
    }
});
</code></pre>
     * @return {Ext.ux.StatusBar} this
     */
    setStatus : function(o){
        o = o || {};

        if(typeof o == 'string'){
            o = {text:o};
        }
        if(o.text !== undefined){
            this.setText(o.text);
        }
        if(o.iconCls !== undefined){
            this.setIcon(o.iconCls);
        }

        if(o.clear){
            var c = o.clear,
                wait = this.autoClear,
                defaults = {useDefaults: true, anim: true};

            if(typeof c == 'object'){
                c = Ext.applyIf(c, defaults);
                if(c.wait){
                    wait = c.wait;
                }
            }else if(typeof c == 'number'){
                wait = c;
                c = defaults;
            }else if(typeof c == 'boolean'){
                c = defaults;
            }

            c.threadId = this.activeThreadId;
            this.clearStatus.defer(wait, this, [c]);
        }
        return this;
    },

    /**
     * Clears the status {@link #text} and {@link #iconCls}. Also supports clearing via an optional fade out animation.
     * @param {Object} config (optional) A config object containing any or all of the following properties.  If this
     * object is not specified the status will be cleared using the defaults below:<ul>
     * <li><tt>anim</tt> {Boolean} : (optional) True to clear the status by fading out the status element (defaults
     * to false which clears immediately).</li>
     * <li><tt>useDefaults</tt> {Boolean} : (optional) True to reset the text and icon using {@link #defaultText} and
     * {@link #defaultIconCls} (defaults to false which sets the text to '' and removes any existing icon class).</li>
     * </ul>
     * @return {Ext.ux.StatusBar} this
     */
    clearStatus : function(o){
        o = o || {};

        if(o.threadId && o.threadId !== this.activeThreadId){
            // this means the current call was made internally, but a newer
            // thread has set a message since this call was deferred.  Since
            // we don't want to overwrite a newer message just ignore.
            return this;
        }

        var text = o.useDefaults ? this.defaultText : this.emptyText,
            iconCls = o.useDefaults ? (this.defaultIconCls ? this.defaultIconCls : '') : '';

        if(o.anim){
            // animate the statusEl Ext.Element
            this.statusEl.el.fadeOut({
                remove: false,
                useDisplay: true,
                scope: this,
                callback: function(){
                    this.setStatus({
	                    text: text,
	                    iconCls: iconCls
	                });

                    this.statusEl.el.show();
                }
            });
        }else{
            // hide/show the el to avoid jumpy text or icon
            this.statusEl.hide();
	        this.setStatus({
	            text: text,
	            iconCls: iconCls
	        });
            this.statusEl.show();
        }
        return this;
    },

    /**
     * Convenience method for setting the status text directly.  For more flexible options see {@link #setStatus}.
     * @param {String} text (optional) The text to set (defaults to '')
     * @return {Ext.ux.StatusBar} this
     */
    setText : function(text){
        this.activeThreadId++;
        this.text = text || '';
        if(this.rendered){
            this.statusEl.setText(this.text);
        }
        return this;
    },

    /**
     * Returns the current status text.
     * @return {String} The status text
     */
    getText : function(){
        return this.text;
    },

    /**
     * Convenience method for setting the status icon directly.  For more flexible options see {@link #setStatus}.
     * See {@link #iconCls} for complete details about customizing the icon.
     * @param {String} iconCls (optional) The icon class to set (defaults to '', and any current icon class is removed)
     * @return {Ext.ux.StatusBar} this
     */
    setIcon : function(cls){
        this.activeThreadId++;
        cls = cls || '';

        if(this.rendered){
	        if(this.currIconCls){
	            this.statusEl.removeClass(this.currIconCls);
	            this.currIconCls = null;
	        }
	        if(cls.length > 0){
	            this.statusEl.addClass(cls);
	            this.currIconCls = cls;
	        }
        }else{
            this.currIconCls = cls;
        }
        return this;
    },

    /**
     * Convenience method for setting the status text and icon to special values that are pre-configured to indicate
     * a "busy" state, usually for loading or processing activities.
     * @param {Object/String} config (optional) A config object in the same format supported by {@link #setStatus}, or a
     * string to use as the status text (in which case all other options for setStatus will be defaulted).  Use the
     * <tt>text</tt> and/or <tt>iconCls</tt> properties on the config to override the default {@link #busyText}
     * and {@link #busyIconCls} settings. If the config argument is not specified, {@link #busyText} and
     * {@link #busyIconCls} will be used in conjunction with all of the default options for {@link #setStatus}.
     * @return {Ext.ux.StatusBar} this
     */
    showBusy : function(o){
        if(typeof o == 'string'){
            o = {text:o};
        }
        o = Ext.applyIf(o || {}, {
            text: this.busyText,
            iconCls: this.busyIconCls
        });
        return this.setStatus(o);
    }
});
Ext.reg('statusbar', Ext.ux.StatusBar);
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
/* global Ext, sitools, ID, i18n, showResponse, alertFailure,clog,window,Base64 */
Ext.namespace('sitools.userProfile');

/*
 * defurl: default page url to load if click on Cancel button url: url to
 * request if click on Login button handler: if request is OK then is called
 * register: url to set to Register button reset: url to set to Reset Password
 * button
 */

sitools.userProfile.LoginUtils = {

    connect : function (config) {
        var url = loadUrl.get('APP_URL') + "/login-details";
        Ext.Ajax.request({
            method : "GET",
            url : url,
            success : function (ret) {
                var Json = Ext.decode(ret.responseText);
                if (Json.success) {
                    var data = Json.data;
                    var delegateLogin = false;
                    var delegateLoginUrl = null;

                    Ext.each(data, function (property) {
                        if (property.name === "Starter.SECURITY.DELEGATE_LOGIN") {
                            delegateLogin = (property.value === "true");
                        }
                        if (property.name === "Starter.SECURITY.DELEGATE_LOGIN_URL") {
                            delegateLoginUrl = property.value;
                        }
                    });

                    if (delegateLogin) {
                        if (Ext.isEmpty(delegateLoginUrl)) {
                            Ext.Msg.alert(i18n.get("label.warning"), "No Logout url defined");
                            return;
                        }
                        sitools.userProfile.LoginUtils.delegateLoginLogout(delegateLoginUrl);
                    } else {
                        sitools.userProfile.LoginUtils.sitoolsLogin(config);
                    }

                } else {
                    // if the parameters are not available perform classic login
                    sitools.userProfile.LoginUtils.sitoolsLogin(config);
                }
            },
            failure : function () {
                // if the parameters are not available perform classic login
                sitools.userProfile.LoginUtils.sitoolsLogin(config);
            }

        });
    },

    logout : function () {
        var url = loadUrl.get('APP_URL') + "/login-details";
        Ext.Ajax.request({
            method : "GET",
            url : url,
            success : function (ret) {
                var Json = Ext.decode(ret.responseText);
                if (Json.success) {
                    var data = Json.data;
                    var delegateLogout = false;
                    var delegateLogoutUrl = null;

                    Ext.each(data, function (property) {
                        if (property.name === "Starter.SECURITY.DELEGATE_LOGOUT") {
                            delegateLogout = (property.value === "true");
                        }
                        if (property.name === "Starter.SECURITY.DELEGATE_LOGOUT_URL") {
                            delegateLogoutUrl = property.value;
                        }
                    });
                        
                    utils_logout(!delegateLogout);
                    if (delegateLogout) {
                        if (Ext.isEmpty(delegateLogoutUrl)) {
                            Ext.Msg.alert(i18n.get("label.warning"), "No Logout url defined");
                            return;
                        }
                        sitools.userProfile.LoginUtils.delegateLoginLogout(delegateLogoutUrl);
                    }

                } else {
                    // if the parameters are not available perform classic
                    // logout
                    utils_logout(true);
                }
            },
            failure : function () {
                // if the parameters are not available perform classic logout
                utils_logout(true);
            }

        });

    },
    /**
     * 
     * @param config
     */
    editProfile : function (callback) {
        var url = loadUrl.get('APP_URL') + "/login-details";
        Ext.Ajax.request({
            method : "GET",
            url : url,
            success : function (ret) {
                var Json = Ext.decode(ret.responseText);
                if (Json.success) {
                    var data = Json.data;
                    var delegateUserManagment = false;
                    var delegateUserManagmentUrl = null;

                    Ext.each(data, function (property) {
                        if (property.name === "Starter.SECURITY.DELEGATE_USER_MANAGMENT") {
                            delegateUserManagment = (property.value === "true");
                        }
                        if (property.name === "Starter.SECURITY.DELEGATE_USER_MANAGMENT_URL") {
                            delegateUserManagmentUrl = property.value;
                        }
                    });
                    
                    if (delegateUserManagment) {
                        if (Ext.isEmpty(delegateUserManagmentUrl)) {
                            Ext.Msg.alert(i18n.get("label.warning"), "No user managment url defined");
                            return;
                        }
                        sitools.userProfile.LoginUtils.delegateLoginLogout(delegateUserManagmentUrl);
                    } else {
                        // if the parameters are not available perform classic
                        // user managment
                        callback.call();
                    }

                } else {
                    // if the parameters are not available perform classic
                    // user managment
                    callback.call();
                }
            },
            failure : function () {
                // if the parameters are not available perform classic logout
                callback.call();
            }

        });

    },

    sitoolsLogin : function (config) {
        new sitools.userProfile.Login(config).show();
    },

    delegateLoginLogout : function (urlTemplate) {
        var url = urlTemplate.replace("{goto}", document.URL);
        window.open(url, "_self");
    },
    
    

};
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
/* global Ext, sitools, ID, i18n, showResponse, alertFailure,clog,window,Base64 */
Ext.namespace('sitools.userProfile');

/*
 * defurl: default page url to load if click on Cancel button url: url to
 * request if click on Login button handler: if request is OK then is called
 * register: url to set to Register button reset: url to set to Reset Password
 * button
 */

sitools.userProfile.Login = Ext.extend(Ext.Window, {
    id : 'winLogin',
    layout : 'hbox',
    width : 392,
    height : 220,
    resizable : false,
    closable : false,
    modal : true,
    initComponent : function () {
        this.title = i18n.get('label.login');
        this.bbar = new Ext.ux.StatusBar({
            text : i18n.get('label.ready'),
            id : 'sbWinLogin',
            iconCls : 'x-status-valid',
            items : [ {
                text : i18n.get('label.passwordLost'),
                hidden : !this.reset,
                scope : this,
                icon : loadUrl.get('APP_URL') + '/common/res/images/icons/wadl.gif',
                iconAlign : 'right',
                handler : function () {
                    Ext.getCmp('winLogin').close();
                    var reset = new sitools.userProfile.resetPassword({
                        closable : this.closable,
                        url : this.reset,
                        handler : this.handler
                    });
                    reset.show();
                }

            } ]
        });
        this.combo = new Ext.form.ComboBox({
            typeAhead : true,
            triggerAction : 'all',
            forceSelection : true,
            allowBlank : false,
            lazyRender : true,
            mode : 'local',
            store : new Ext.data.ArrayStore({
                id : 0,
                fields : [ 'myId', 'displayText' ],
                data : [ [ 1, i18n.get('label.userPortal') ], [ 2, i18n.get('label.administration') ] ]
            }),
            valueField : 'myId',
            displayField : 'displayText',
            anchor : '80%',
            value : 1,
            fieldLabel : i18n.get('label.target'),
            hideLabel : true
        });
        if (this.chooseLocation) {
            this.combo.setVisible(true);
            this.combo.hideLabel = false;
        } else {
            this.combo.setVisible(false);
//            this.setSize(392, 160);
            this.setSize(392, 175);
        }
        this.items = [ {
            xtype : 'form',
            frame : true,
            border : false,
            buttonAlign : 'center',
            id : 'frmLogin',
            width : 392,
            labelWidth : 100,
            padding : "10px 10px 0px 60px",
            bodyStyle : "background-image: url("+loadUrl.get('APP_URL')+"/common/res/images/ux/login-big.gif);" +
			"background-position: top left;" +
			"background-repeat: no-repeat;",
            items : [ {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.login'),
                name : 'login',
                id : 'logId',
                allowBlank : false,
                anchor : '80%',
                listeners : {
                    afterrender : function (login) {
                        login.focus(false, 100);
                    }
                }
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.password'),
                name : 'password',
                id : 'pwdId',
                allowBlank : false,
                inputType : 'password',
                anchor : '80%',
                listeners : {
                    scope : this,
                    specialkey : function (field, e) {
                        if (e.getKey() == e.ENTER) {
                            this.getAuth();
                        }
                    }
                }
            }, this.combo ],
            buttons : [ {
                text : i18n.get('label.login'),
                handler : this.getAuth,
                scope : this
            }, {
                text : i18n.get('label.reset'),
                handler : function () {
                    Ext.getCmp('frmLogin').getForm().reset();
                    Ext.getCmp('sbWinLogin').setStatus({
                        text : i18n.get('label.ready'),
                        iconCls : 'x-status-valid'
                    });
                }
            }, {
                text : i18n.get('label.cancel'),
                hidden : !this.defurl,
                scope : this,
                handler : function () {
                    window.location.href = this.defurl;
                }
            }, {
                text : i18n.get('label.register'),
                hidden : !this.register,
                scope : this,
                icon : loadUrl.get('APP_URL') + '/common/res/images/icons/refresh.png',
                handler : function () {
                    Ext.getCmp('winLogin').close();
                    var register = new sitools.userProfile.Register({
                        closable : this.closable,
                        url : this.register,
                        login : this.url,
                        handler : this.handler
                    });
                    register.show();
                }
            } ]
        } ];

        sitools.userProfile.Login.superclass.initComponent.call(this);
    },

    getAuth : function () {
        /*
         * var usr = Ext.getCmp('logId').getValue(); var pwd =
         * Ext.getCmp('pwdId').getValue(); var tok = usr + ':' + pwd; var hash =
         * Base64.encode(tok); var auth = 'Basic ' + hash;
         * Ext.util.Cookies.set('hashCode', auth);
         * Ext.apply(Ext.Ajax.defaultHeaders, { "Authorization" : auth });
         * this.login();
         */

        Ext.util.Cookies.set('A1', "");
        Ext.util.Cookies.set('userLogin', "");
        Ext.util.Cookies.set('scheme', "");
        Ext.util.Cookies.set('algorithm', "");
        Ext.util.Cookies.set('realm', "");
        Ext.util.Cookies.set('nonce', "");
        Ext.util.Cookies.set('hashCode', "");
        Ext.apply(Ext.Ajax.defaultHeaders, {
            "Authorization" : ""
        });

        Ext.Ajax.request({
            url : this.url,
            method : 'GET',
            scope : this,
            success : function (response, opts) {
                var Json = Ext.decode(response.responseText);
                var date = new Date();
                if (!Ext.isEmpty(Json.data)) {
                    if (Json.data.scheme == 'HTTP_Digest') {
                        var auth = new Digest({
                            usr : Ext.getCmp('logId').getValue(),
                            pwd : Ext.getCmp('pwdId').getValue(),
                            realm : Json.data.realm
                        });
                        var A1 = auth.getA1();

                        // stockage en cookie du mode d'authorization
                        Ext.util.Cookies.set('A1', A1);
                        Ext.util.Cookies.set('userLogin', auth.usr, date.add(Date.MINUTE, 1));
                        Ext.util.Cookies.set('scheme', Json.data.scheme);
                        Ext.util.Cookies.set('algorithm', Json.data.algorithm);
                        Ext.util.Cookies.set('realm', auth.realm);
                        Ext.util.Cookies.set('nonce', Json.data.nonce);

                    } else if (Json.data.scheme == "HTTP_Basic") {
                        var usr = Ext.getCmp('logId').getValue();
                        var pwd = Ext.getCmp('pwdId').getValue();
                        var tok = usr + ':' + pwd;
                        var hash = Base64.encode(tok);
                        var auth = 'Basic ' + hash;

                        // stockage en cookie du mode d'authorization
                        Ext.util.Cookies.set('userLogin', usr, date.add(Date.MINUTE, 1));
                        Ext.util.Cookies.set('scheme', Json.data.scheme);
                        Ext.util.Cookies.set('hashCode', auth, date.add(Date.MINUTE, 1));
                    }
                }

                this.login();
            },
            failure : alertFailure
        });

    },
    login : function () {
        if (!Ext.getCmp('frmLogin').getForm().isValid()) {
            Ext.getCmp('sbWinLogin').setStatus({
                text : i18n.get('warning.checkForm'),
                iconCls : 'x-status-error'
            });
            return;
        }

        Ext.getCmp('winLogin').body.mask();
        Ext.getCmp('sbWinLogin').showBusy();
        Ext.Ajax.request({
            url : this.url,
            method : 'GET',
            scope : this,
            success : function (response, opts) {
                try {
                    var Json = Ext.decode(response.responseText);
                    if (Json.success) {
                        // var date = new Date();
                        Ext.apply(Ext.Ajax.defaultHeaders, {
                            "Authorization" : Ext.util.Cookies.get('hashCode')
                        });

                        Ext.getCmp('winLogin').close();
                        // this.handler.call(this.scope || this);
                        if (this.chooseLocation) {
                            if (this.combo.getValue() == 1) {
                                window.location.href = loadUrl.get('APP_URL') + '/login-redirect?kwd=/client-user/index.html';
                                // window.location.href =
                                // "/sitools/client-user/index.html?authorization="
                                // + hash;
                            } else {
                                Ext.Ajax.request({
                                    url : loadUrl.get('APP_URL') + '/login-redirect?kwd=/client-admin',
                                    method : "GET",
                                    success : function (response) {
                                        Ext.Msg.alert('error login.js redirect with authorization');
                                    }
                                });
                                // window.location.href =
                                // "/sitools/client-admin";
                            }
                        } else {
                            window.location.reload();
                        }

                    } else {
                        Ext.util.Cookies.set('userLogin', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));
                        Ext.util.Cookies.set('scheme', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));
                        Ext.util.Cookies.set('hashCode', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));

                        var txt = i18n.get('warning.serverError') + ': ' + Json.message;
                        Ext.getCmp('winLogin').body.unmask();
                        Ext.getCmp('sbWinLogin').setStatus({
                            // text: ret.error ? ret.error :
                            // i18n.get('warning.serverUnreachable'),
                            text : txt,
                            iconCls : 'x-status-error'
                        });

                    }
                } catch (err) {
                    Ext.Msg.alert(i18n.get('label.error'), err);
                }
            },
            failure : function (response, opts) {
                Ext.util.Cookies.set('userLogin', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));
                Ext.util.Cookies.set('scheme', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));
                Ext.util.Cookies.set('hashCode', "", new Date().add(Date.MINUTE, COOKIE_DURATION * -1));

                var txt;
                if (response.status == 200) {
                    var ret = Ext.decode(response.responseText).error;
                    txt = i18n.get('msg.error') + ': ' + ret;
                } else {
                    txt = i18n.get('warning.serverError') + ': ' + response.statusText;
                }
                Ext.getCmp('winLogin').body.unmask();
                Ext.getCmp('sbWinLogin').setStatus({
                    // text: ret.error ? ret.error :
                    // i18n.get('warning.serverUnreachable'),
                    text : txt,
                    iconCls : 'x-status-error'
                });
            }
        });
    }

});

Ext.reg('s-login', sitools.userProfile.Login);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n,document*/
Ext.namespace('sitools.userProfile');	
/*
 * config { url + handler }
 */
/**
 * @cfg {string} url the url to request when register
 * @cfg {string} login the url to login  
 * @class sitools.userProfile.Register
 * @extends Ext.Window
 */
sitools.userProfile.Register = Ext.extend(Ext.Window, {
    id: 'winRegister',
	layout: 'hbox',
	width: 420,
	height: 480,
	resizable: false,
	closable: false,
	modal: true,
  
	initComponent: function () {
		this.title = i18n.get('label.register');
		this.captchaUrl = loadUrl.get('APP_URL') + loadUrl.get('APP_INSCRIPTIONS_USER_URL') + '/captcha?width=300&height=50';
		
	    this.bbar = new Ext.ux.StatusBar({
			text: i18n.get('label.ready'),
			id: 'sbWinRegister',
			iconCls: 'x-status-valid'
		});
	    
	    this.captcha = new Ext.BoxComponent({
	        id : 'captchaBox',
	        autoEl: {
	            tag: 'img',
	            src: this.captchaUrl + '&_dc=' + new Date().getTime()
	        },
	        fieldLabel : i18n.get('label.captcha'),
	        height : 50,
	        width : 300,
	        anchor: '100%'
	    });
	    
	    this.items = [{
	    	xtype: 'form',
//			frame: false,
			border: false,
			buttonAlign: 'center',
			id: 'frmRegister',
			bodyStyle: 'padding:10px 10px 0px 60px; background:url("'+loadUrl.get('APP_URL')+'/common/res/images/ux/register-big.gif") no-repeat;',
			width: 400,
			height : 430,
			labelWidth: 120,
			items: [{
				xtype: 'textfield',
				fieldLabel: i18n.get('label.login'),
				name: 'identifier',
				id: 'regLogin',
				allowBlank: false,
	            vtype: 'uniquelogin',
	            anchor: '100%'
			}, {
				xtype: 'textfield',
				fieldLabel: i18n.get('label.firstName'),
				name: 'firstName',
				id: 'regFirstName',
				allowBlank: false,
	            anchor: '100%'
			}, {
				xtype: 'textfield',
				fieldLabel: i18n.get('label.lastName'),
				name: 'lastName',
				id: 'regLastName',
				allowBlank: false,
	            anchor: '100%'
			}, {
				xtype: 'textfield',
				fieldLabel: i18n.get('label.password'),
				name: 'password',
				allowBlank: false,
				inputType: 'password',
	            vtype: 'passwordlength',
	            id: 'pass1',
	            anchor: '100%'
			}, {
				xtype: 'textfield',
				fieldLabel: i18n.get('label.confirmPassword'),
				name: 'cpassword',
				submitValue: false,
				allowBlank: false,
				inputType: 'password',
	            id: 'pass2',
	            initialPassField: 'pass1',
	            vtype: 'password',
	            anchor: '100%'
			}, {
				xtype: 'textfield',
				fieldLabel: i18n.get('label.email'),
	            id: 'regEmail',
				name: 'email',
				vtype: 'uniqueemail',
				allowBlank: false,
	            validationEvent: '',
	            anchor: '100%'
			}, {
                xtype : 'textfield',
                name : 'organisation',
                fieldLabel : i18n.get('label.organisation'),
                anchor : '100%'
            }, {
				xtype: 'textarea',
				fieldLabel: i18n.get('label.comment'),
	            id: 'regComment',
				name: 'comment',
	            validationEvent: '',
	            height: 40,
	            anchor: '100%'
			}, 
			    this.captcha,
			{
			    xtype: 'button',
			    text: i18n.get('label.captchaReload'),
			    icon : loadUrl.get('APP_URL') + '/common/res/images/icons/refresh.png',
			    x : 150,
			    arrowAlign : 'right',
			    reloadUrl : this.captchaUrl,
                handler : function () {
                    Ext.util.Cookies.clear('captcha');
                    var box = Ext.get('captchaBox');
                    box.dom.src = this.reloadUrl + '&_dc=' + new Date().getTime();
                    box.slideIn('l');
                }
			},
			{
                xtype: 'textfield',
                fieldLabel: i18n.get('label.fieldCaptcha'),
                name: 'captcha',
                id: 'captcha',
                allowBlank: false,
                anchor: '100%'
            },
            {
				xtype: 'checkbox',
				fieldLabel: String.format(i18n.get('label.acceptCGU'), URL_CGU),
	            id: 'acceptCGU',
				name: 'acceptCGU',
	            height: 40,
	            anchor: '100%', 
	            submitValue : false
			}],
			buttons: [
				{ text: i18n.get('label.register'), handler: this.register, scope: this },
				{ text: i18n.get('label.reset'), reloadUrl : this.captchaUrl, handler: function () {
						Ext.getCmp('frmRegister').getForm().reset();
						Ext.getCmp('sbWinRegister').setStatus({
							text: i18n.get('label.ready'),
				        	iconCls: 'x-status-valid'
						});
						Ext.util.Cookies.clear('captcha');
	                    var box = Ext.get('captchaBox');
	                    box.dom.src = this.reloadUrl + '&_dc=' + new Date().getTime();
	                    box.slideIn('l');
					}
				},
					{ text: i18n.get('label.login'), hidden: !this.register, scope: this,
					icon: loadUrl.get('APP_URL') + '/common/res/images/icons/refresh.png',
					handler: function () {
		        		Ext.getCmp('winRegister').close();
		        		var login = new sitools.userProfile.Login({
		        			closable: this.closable,
		        			url: this.login,
		        			register: this.url,
		        			handler: this.handler
		        		});
		        		login.show();
					}
				}
				]
	    	}];
        sitools.userProfile.Register.superclass.initComponent.call(this);
	},
	
    register : function () {
        var f = Ext.getCmp('frmRegister').getForm();
        if (!f.findField('acceptCGU').getValue()) {
        	Ext.getCmp('sbWinRegister').setStatus({
                text: i18n.get('label.mustAcceptCGU'),
                iconCls: 'x-status-error'
            });;
        	return;
        }
        if (! f.isValid()) {
            Ext.getCmp('sbWinRegister').setStatus({
                text: i18n.get('warning.checkForm'),
                iconCls: 'x-status-error'
            });
            this.reloadCaptcha();
            return;
        }
        var putObject = new Object();
		putObject.properties = [];
        
        Ext.iterate(f.getValues(), function (key, value) {
            if (key == 'organisation') {
                putObject.properties.push({
                	name : "organisation", 
                	value : value,
                	scope : "Editable"
            	});
            } else {
                if (key != 'captcha') {
                    putObject[key] = value;
                }
            }
        }, this);
		
        var cook = Ext.util.Cookies.get('captcha');
        var capt = f.findField('captcha').getValue();
        
        Ext.getCmp('winRegister').body.mask();
        Ext.getCmp('sbWinRegister').showBusy();
		Ext.Ajax.request({
			url: this.url,
			method: 'POST',
			jsonData: putObject,
			params : {
                "captcha.id" : cook,
                "captcha.key" : capt
            },
			scope: this,
        	success: function (response, opts) {
	    		var json = Ext.decode(response.responseText);
	    		if (json.success){
	    		    new Ext.ux.Notification({
                        iconCls : 'x-icon-information',
                        title : i18n.get('label.information'),
                        html : i18n.get('label.registerSent'),
                        autoDestroy : true,
                        hideDelay : 1000
                    }).show(document);
	    			Ext.getCmp('winRegister').close();
	    		}
	    		else {
					Ext.getCmp('winRegister').body.unmask();
		            Ext.getCmp('sbWinRegister').setStatus({
		            	text : json.message,
		                iconCls: 'x-status-error'
		            });	    			
	    			
	    		}
	    		if (this.handler !== null && this.handler !== undefined) {
	    			this.handler.call(this.scope || this);
	    		}
            },
            failure: function (response, opts) {
        		var txt;
        		if (response.status == 200) {
            		var ret = Ext.decode(response.responseText).message;
            		txt = i18n.get('msg.error') + ': ' + ret;
        		} else if (response.status == 403){
        		    txt = i18n.get('msg.wrongCaptcha');        			
        		} else {
        		    txt = i18n.get('warning.serverError') + ': ' + response.statusText;
        		}
        		Ext.getCmp('winRegister').body.unmask();
	            Ext.getCmp('sbWinRegister').setStatus({
	            	text : txt,
	                iconCls: 'x-status-error'
	            });
	            this.reloadCaptcha();
	    	}
        });
    },
    
    reloadCaptcha : function () {
        Ext.util.Cookies.clear('captcha');
        var box = Ext.get('captchaBox');
        box.dom.src = this.captchaUrl + '&_dc=' + new Date().getTime();
        box.slideIn('l');
        
        var f = Ext.getCmp('frmRegister').getForm();
        var capt = f.findField('captcha').setValue("");

        
    }
   
});

Ext.reg('s-register', sitools.userProfile.Register);
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
Ext.namespace('sitools.userProfile');

/**
 * A specific window to reset user password 
 * @cfg {boolean} closable Window config
 * @cfg {string} url The url to send reset request
 * @cfg {} handler A method to call after success 
 * @class sitools.userProfile.resetPassword
 * @extends Ext.Window
 */
sitools.userProfile.resetPassword = Ext.extend(Ext.Window, {
    id : 'winPassword',
    layout : 'hbox',
    width : 420,
    height : 183,
    resizable : false,
    // closable: true,
    modal : true,

    initComponent : function () {
        this.title = i18n.get('label.resetPassword');
        this.bbar = new Ext.ux.StatusBar({
            text : i18n.get('label.ready'),
            id : 'sbWinPassword',
            iconCls : 'x-status-valid'
        });
        this.items = [ {
            xtype : 'form',
//            frame : false,
            border : false,
            buttonAlign : 'center',
            id : 'frmResetPassword',
            bodyStyle : 'padding:10px 10px 0px 60px; background:url("'+loadUrl.get('APP_URL')+'/common/res/images/ux/login-big.gif") no-repeat;',
            width : 400,
            labelWidth : 120,
            items : [ {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.login'),
                name : 'identifier',
                id : 'regLogin',
                allowBlank : false,
                anchor : '100%'
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.email'),
                id : 'regEmail',
                name : 'email',
                vtype : 'uniqueemail',
                allowBlank : false,
                validationEvent : '',
                anchor : '100%'
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.emailConfirm'),
                id : 'regEmailConfirm',
                name : 'emailConfirm',
                vtype : 'uniqueemail',
                allowBlank : false,
                validationEvent : '',
                anchor : '100%'
            } ],
            buttons : [ {
                text : i18n.get('label.resetPassword'),
                handler : this.reset,
                scope : this
            }, {
                text : i18n.get('label.reset'),
                handler : function () {
                    Ext.getCmp('frmResetPassword').getForm().reset();
                    Ext.getCmp('sbWinPassword').setStatus({
                        text : i18n.get('label.ready'),
                        iconCls : 'x-status-valid'
                    });
                }
            } ]
        } ];
        sitools.userProfile.resetPassword.superclass.initComponent.call(this);
    },
    reset : function () {
        var f = Ext.getCmp('frmResetPassword').getForm();
        if (f.findField('email').getValue() != f.findField('emailConfirm').getValue()) {
            Ext.getCmp('sbWinPassword').setStatus({
                text : i18n.get('warning.checkForm'),
                iconCls : 'x-status-error'
            });
            return;
        }

        if (!f.isValid()) {
            Ext.getCmp('sbWinPassword').setStatus({
                text : i18n.get('warning.checkForm'),
                iconCls : 'x-status-error'
            });
            return;
        }
        var putObject = new Object();
        Ext.iterate(f.getValues(), function (key, value) {
            if (key != 'emailConfirm') {
                putObject[key] = value;
            }
        }, this);

        Ext.getCmp('winPassword').body.mask();
        Ext.getCmp('sbWinPassword').showBusy();
        Ext.Ajax.request({
            url : this.url,
            method : 'PUT',
            jsonData : putObject,
            scope : this,
            success : function (response, opts) {
                var json = Ext.decode(response.responseText);
                if (json.success) {
                    Ext.getCmp('winPassword').body.unmask();
                    Ext.getCmp('sbWinPassword').setStatus({
                        text : json.message,
                        iconCls : 'x-status-valid'
                    });
                    Ext.getCmp('winPassword').close();
                    
                    var notify = new Ext.ux.Notification({
                        iconCls : 'x-icon-information',
                        title : i18n.get('label.information'),
                        html : i18n.get('label.passwordSent') + json.message,
                        autoDestroy : true,
                        hideDelay : 1300
                    });
                    notify.show(document);
                } else {
                    Ext.getCmp('winPassword').body.unmask();
                    Ext.getCmp('sbWinPassword').setStatus({
                        text : json.message,
                        iconCls : 'x-status-error'
                    });

                }
                if (this.handler !== null && this.handler !== undefined) {
                    this.handler.call(this.scope || this);
                }
            },
            failure : function (response, opts) {
                var txt;
                if (response.status == 200) {
                    var ret = Ext.decode(response.responseText).message;
                    txt = i18n.get('msg.error') + ': ' + ret;
                } else {
                    txt = i18n.get('warning.serverError') + ': ' + response.statusText;
                }
                Ext.getCmp('winPassword').body.unmask();
                Ext.getCmp('sbWinPassword').setStatus({
                    text : txt,
                    iconCls : 'x-status-error'
                });
            }
        });
    }
});
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
/* global Ext, sitools, i18n,document */
Ext.namespace('sitools.userProfile');
/*
 * config { url + handler }
 */
sitools.userProfile.editProfile = Ext.extend(Ext.Panel, {
//    id : 'winEditProfile',
//    layout : 'hbox',
//    width : 420,
//    height : 410,
//    resizable : false,
//    closable : true,
//    modal : true,
	padding : "10px 10px 0px 60px",
	frame : true,
	layout : "fit", 

    initComponent : function () {
    	this.bodyStyle = "background-image: url("+loadUrl.get('APP_URL')+"/common/res/images/ux/login-big.gif);" +
    			"background-position: top left;" +
    			"background-repeat: no-repeat;";

//        this.title = i18n.get('label.editProfile');
        this.bbar = new Ext.ux.StatusBar({
            text : i18n.get('label.ready'),
            id : 'sbWinEditProfile',
            iconCls : 'x-status-valid'
        });

        var storeProperties = new Ext.data.JsonStore({
            fields : [ {
                name : 'name',
                type : 'string'
            }, {
                name : 'value',
                type : 'string'
            }, {
                name : 'scope',
                type : 'string'
            } ],
            autoLoad : false
        });
        var smProperties = new Ext.grid.RowSelectionModel({
            singleSelect : true
        });

        var cmProperties = new Ext.grid.ColumnModel({
            columns : [ {
                header : i18n.get('headers.name'),
                dataIndex : 'name',
                editor : new Ext.form.TextField({
                    readOnly : true
                })
            }, {
                header : i18n.get('headers.value'),
                dataIndex : 'value',
                editor : new Ext.form.TextField({
                    allowBlank : false
                })
            }],
            defaults : {
                sortable : false,
                width : 100
            }
        });

        this.gridProperties = new Ext.grid.EditorGridPanel({
            title : i18n.get('title.properties'),
            id : 'userGridProperties',
            height : 130,
            autoScroll : true,
            clicksToEdit : 1,
            store : storeProperties,
            cm : cmProperties,
            sm : smProperties,
            viewConfig : {
                forceFit : true,
                getRowClass : function (row, col) { 
                    var data = row.data;
                    if (data.scope == 'ReadOnly') {
                        return "row-grid-readOnly"; 
                    }
                } 
            },
            listeners : {
                beforeedit : function (e) {
                    var scope = e.record.data.scope;
                    var name = e.field;
                    if (scope == 'ReadOnly' || name == 'name') {
                        return false;
                    }
                }
            }
        });
        
        this.items = [ {
            xtype : 'form',
            flex : 1, 
            border : false,
            buttonAlign : 'center',
            id : 'frmEditProfile',
            labelWidth : 120,
            items : [ {
                xtype : 'textfield',
                name : 'identifier',
                fieldLabel : i18n.get('label.login'),
                anchor : '100%',
                allowBlank : false,
                readOnly : true,
                style : {
                    color : '#C0C0C0'
                },
                id : "nameField"
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.firstName'),
                name : 'firstName',
                id : 'regFirstName',
                allowBlank : false,
                anchor : '100%'
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.lastName'),
                name : 'lastName',
                id : 'regLastName',
                allowBlank : false,
                anchor : '100%'
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.password'),
                anchor : '100%',
                inputType : 'password',
                name : 'secret',
                value : '',
                id : "passwordField",
                vtype : 'passwordlength'
            }, {
                id : "confirmSecret",
                xtype : 'textfield',
                fieldLabel : i18n.get('label.confirmPassword'),
                anchor : '100%',
                inputType : 'password',
                initialPassField : 'passwordField',
                vtype : 'password',
                name : 'confirmSecret',
                submitValue : false,
                value : ''
            }, {
                xtype : 'textfield',
                fieldLabel : i18n.get('label.email'),
                id : 'regEmail',
                name : 'email',
                vtype : 'uniqueemail',
                allowBlank : false,
                validationEvent : '',
                anchor : '100%'
            }, this.gridProperties ],
            buttons : [ {
                text : i18n.get('label.saveEdit'),
                x : 30,
                handler : this.saveEdit,
                scope : this
            }]
        } ];
        
        sitools.userProfile.editProfile.superclass.initComponent.call(this);
        
    },

    saveEdit : function () {
        var f = Ext.getCmp('frmEditProfile').getForm();

        if (!f.isValid()) {
            Ext.getCmp('sbWinEditProfile').setStatus({
                text : i18n.get('warning.checkForm'),
                iconCls : 'x-status-error'
            });
            return;
        }

        var putObject = f.getValues();
        putObject.properties = [];
        this.gridProperties.getStore().each(function (item) {
            putObject.properties.push({
                name : item.data.name,
                value : item.data.value,
                scope : item.data.scope
            });
        });

        this.body.mask();
        Ext.getCmp('sbWinEditProfile').showBusy();

        Ext.Ajax.request({
            url : this.url,
            method : 'PUT',
            jsonData : putObject,
            scope : this,
            success : function (response, opts) {
                var json = Ext.decode(response.responseText);
                if (json.success) {
                    this.ownerCt.close();
                    
                    var notify = new Ext.ux.Notification({
                        iconCls : 'x-icon-information',
                        title : i18n.get('label.information'),
                        html : json.message,
                        autoDestroy : true,
                        hideDelay : 1000
                    });
                    notify.show(document);
                } else {
                    Ext.getCmp('winEditProfile').body.unmask();
                    Ext.getCmp('sbWinEditProfile').setStatus({
                        text : json.message,
                        iconCls : 'x-status-error'
                    });

                }
                if (this.handler !== null && this.handler !== undefined) {
                    this.handler.call(this.scope || this, putObject);
                }
            },
            failure : function (response, opts) {
                var txt;
                if (response.status == 200) {
                    var ret = Ext.decode(response.responseText).message;
                    txt = i18n.get('msg.error') + ': ' + ret;
                } else {
                    txt = i18n.get('warning.serverError') + ': ' + response.statusText;
                }
                Ext.getCmp('winEditProfile').body.unmask();
                Ext.getCmp('sbWinEditProfile').setStatus({
                    text : txt,
                    iconCls : 'x-status-error'
                });
            }
        });
    },

    onRender : function () {
        sitools.userProfile.editProfile.superclass.onRender.apply(this, arguments);
        if (this.url) {
            Ext.Ajax.request({
                url : this.url,
                method : 'GET',
                scope : this,
                success : function (ret) {
                    var f = this.findByType('form')[0].getForm();
                    var data = Ext.decode(ret.responseText);
                    if (data.user !== undefined) {
                        f.setValues(data.user);
                        f.findField('secret').setValue('');
                        if (!Ext.isEmpty(data.user.properties)) {
                            Ext.each(data.user.properties, function (property) {
                                var rec = new Ext.data.Record({
                                    name : property.name,
                                    value : property.value,
                                    scope : property.scope
                                });
                                this.gridProperties.getStore().add(rec);
                            }, this);
                        }
                    }
                },
                failure : alertFailure
            });
        }
    },
    /**
     * Method called when trying to show this component with fixed navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInFixedNav : function (me, config) {
        Ext.apply(config.windowSettings, {
            width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
            height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
        });
        SitoolsDesk.openModalWindow(me, config);
    }, 
    /**
     * Method called when trying to show this component with Desktop navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInDesktopNav : function (me, config) {
        Ext.apply(config.windowSettings, {
            width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
            height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
        });
        SitoolsDesk.openModalWindow(me, config);
    }

});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
var loginErrLength = 'Login minimum 4 character !';
var loginErrUnique = 'Login already in use !';
var loginSuccess = 'Login avaliable';
var emailErrFormat = 'Email not valid !';
var emailErrUnique = 'Email already in use !';
var emailSuccess = 'Email valid & avaliable';

Ext.apply(Ext.form.VTypes, {
    uniqueloginMask : /[a-z0-9_\.\-@\+]/i,
	uniquelogin : function(val) {
        if (val.length < 4) {
            Ext.apply(Ext.form.VTypes, {
                uniqueloginText: loginErrLength
            });
            return false;
        } else {
            /*Ext.Ajax.request({
                url: 'user/ext_is_unique_login',
                method: 'POST',
                params: 'login=' + val,
                success: function(o) {
                    if (o.responseText == 0) {
                        resetLoginValidator(false);
                        Ext.apply(Ext.form.VTypes, {
                            uniqueloginText: loginErrUnique
                        });
                        return false;
                    } else {
                        resetLoginValidator(true);
                    }
                }
            });*/
            return true;
        }
	},
	uniqueloginText : loginErrUnique,

    uniqueemailMask : /[a-z0-9_\.\-@\+]/i,
    uniqueemail : function(val) {
        var uniqueemail = /^(\w+)([\-+.][\w]+)*@(\w[\-\w]*\.){1,5}([A-Za-z]){2,6}$/;
        if (uniqueemail.test(val)) {
        	/*
            Ext.Ajax.request({
                url: BASE_URL + 'user/ext_is_unique_email',
                method: 'POST',
                params: 'email=' + val,
                success: function(o) {
                    if (o.responseText == 0) {
                        resetEmailValidator(false);
                        Ext.apply(Ext.form.VTypes, {
                            uniqueemailText: emailErrUnique
                        });
                    } else {
                        resetEmailValidator(true);
                    }
                }
            });*/
            return true;
        } else {
            return false;
        }

    },
    uniqueemailText : emailErrFormat,

    password : function(val, field) {
        if (field.initialPassField) {
            var pwd = Ext.getCmp(field.initialPassField);
            return (val == pwd.getValue());
        }
        return true;
    },
    passwordText : 'Passwords do not match',

    passwordlength : function(val) {
        if (val.length < 6 || val.length > 40) {
            return false;
        } else {
            return true;
        }
    },
    passwordlengthText : 'Invalid Password Length. It must be between 6 and 40'
});

function resetLoginValidator(is_error) {
	Ext.apply(Ext.form.VTypes, {
		uniquelogin : function(val) {
            if (val.length < 4) {
                Ext.apply(Ext.form.VTypes, {
                    uniqueloginText: loginErrLength
                });
                return false;
            } else {
            	/*
                Ext.Ajax.request({
                    url: 'user/ext_is_unique_login',
                    method: 'POST',
                    params: 'login=' + val,
                    success: function(o) {
                        if (o.responseText == 0) {
                            resetLoginValidator(false);
                        } else {
                            resetLoginValidator(true);
                        }
                    }
                });
                return is_error;
                */return true;
            }
		}
	});
}

function resetEmailValidator(value) {
    Ext.apply(Ext.form.VTypes, {
        uniqueemail : function(val) {
            var uniqueemail = /^(\w+)([\-+.][\w]+)*@(\w[\-\w]*\.){1,5}([A-Za-z]){2,6}$/;
            if (uniqueemail.test(val)) {
                /*Ext.Ajax.request({
                    url: BASE_URL + 'user/ext_is_unique_email',
                    method: 'POST',
                    params: 'email=' + val,
                    success: function(o) {
                        if (o.responseText == 0) {
                            resetEmailValidator(false);
                            Ext.apply(Ext.form.VTypes, {
                                uniqueemailText: emailErrUnique
                            });
                        } else {
                            resetEmailValidator(true);
                        }
                    }
                });*/return true;
            } else {
                return false;
            }
            return (value);
        }
    });
}
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*!
 * managediframe version 2.1.5
 * url : https://code.google.com/p/managediframe/
 */
/*!
 * ux.ManagedIFrame for ExtJS Library 3.1+
 * Copyright(c) 2008-2009 Active Group, Inc.
 * licensing@theactivegroup.com
 * http://licensing.theactivegroup.com
 */
 /**
  * @class Ext.ux.plugin.VisibilityMode
  * @version 1.3.1
  * @author Doug Hendricks. doug[always-At]theactivegroup.com
  * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
  * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
  * Commercial Developer License (CDL) is available at http://licensing.theactivegroup.com.
  * @singleton
  * @static
  * @desc This plugin provides an alternate mechanism for hiding Ext.Elements and a new hideMode for Ext.Components.<br />
  * <p>It is generally designed for use with all browsers <b>except</b> Internet Explorer, but may used on that Browser as well.
  * <p>If included in a Component as a plugin, it sets it's hideMode to 'nosize' and provides a new supported
  * CSS rule that sets the height and width of an element and all child elements to 0px (rather than
  * 'display:none', which causes DOM reflow to occur and re-initializes nested OBJECT, EMBED, and IFRAMES elements)
  * @example
   var div = Ext.get('container');
   new Ext.ux.plugin.VisibilityMode().extend(div);
   //You can override the Element (instance) visibilityCls to any className you wish at any time
   div.visibilityCls = 'my-hide-class';
   div.hide() //or div.setDisplayed(false);

   // In Ext Layouts:
   someContainer.add({
     xtype:'flashpanel',
     plugins: [new Ext.ux.plugin.VisibilityMode() ],
     ...
    });

   // or, Fix a specific Container only and all of it's child items:
   // Note: An upstream Container may still cause Reflow issues when hidden/collapsed

    var V = new Ext.ux.plugin.VisibilityMode({ bubble : false }) ;
    new Ext.TabPanel({
     plugins     : V,
     defaults    :{ plugins: V },
     items       :[....]
    });
  */

 Ext.namespace('Ext.ux.plugin');
 Ext.onReady(function(){

   /* This important rule solves many of the <object/iframe>.reInit issues encountered
    * when setting display:none on an upstream(parent) element (on all Browsers except IE).
    * This default rule enables the new Panel:hideMode 'nosize'. The rule is designed to
    * set height/width to 0 cia CSS if hidden or collapsed.
    * Additional selectors also hide 'x-panel-body's within layouts to prevent
    * container and <object, img, iframe> bleed-thru.
    */
    var CSS = Ext.util.CSS;
    if(CSS){
        CSS.getRule('.x-hide-nosize') || //already defined?
            CSS.createStyleSheet('.x-hide-nosize{height:0px!important;width:0px!important;border:none!important;zoom:1;}.x-hide-nosize * {height:0px!important;width:0px!important;border:none!important;zoom:1;}');
        CSS.refreshCache();
    }

});

(function(){

      var El = Ext.Element, A = Ext.lib.Anim, supr = El.prototype;
      var VISIBILITY = "visibility",
        DISPLAY = "display",
        HIDDEN = "hidden",
        NONE = "none";

      var fx = {};

      fx.El = {

            /**
             * Sets the CSS display property. Uses originalDisplay if the specified value is a boolean true.
             * @param {Mixed} value Boolean value to display the element using its default display, or a string to set the display directly.
             * @return {Ext.Element} this
             */
           setDisplayed : function(value) {
                var me=this;
                me.visibilityCls ? (me[value !== false ?'removeClass':'addClass'](me.visibilityCls)) :
                    supr.setDisplayed.call(me, value);
                return me;
            },

            /**
             * Returns true if display is not "none" or the visibilityCls has not been applied
             * @return {Boolean}
             */
            isDisplayed : function() {
                return !(this.hasClass(this.visibilityCls) || this.isStyle(DISPLAY, NONE));
            },
            // private
            fixDisplay : function(){
                var me = this;
                supr.fixDisplay.call(me);
                me.visibilityCls && me.removeClass(me.visibilityCls);
            },

            /**
             * Checks whether the element is currently visible using both visibility, display, and nosize class properties.
             * @param {Boolean} deep (optional) True to walk the dom and see if parent elements are hidden (defaults to false)
             * @return {Boolean} True if the element is currently visible, else false
             */
            isVisible : function(deep) {
                var vis = this.visible ||
                    (!this.isStyle(VISIBILITY, HIDDEN) &&
                        (this.visibilityCls ?
                            !this.hasClass(this.visibilityCls) :
                                !this.isStyle(DISPLAY, NONE))
                      );

                  if (deep !== true || !vis) {
                    return vis;
                  }

                  var p = this.dom.parentNode,
                      bodyRE = /^body/i;

                  while (p && !bodyRE.test(p.tagName)) {
                    if (!Ext.fly(p, '_isVisible').isVisible()) {
                      return false;
                    }
                    p = p.parentNode;
                  }
                  return true;

            },
            //Assert isStyle method for Ext 2.x
            isStyle: supr.isStyle || function(style, val) {
                return this.getStyle(style) == val;
            }

        };

 //Add basic capabilities to the Ext.Element.Flyweight class
 Ext.override(El.Flyweight, fx.El);

 Ext.ux.plugin.VisibilityMode = function(opt) {

    Ext.apply(this, opt||{});

    var CSS = Ext.util.CSS;

    if(CSS && !Ext.isIE && this.fixMaximizedWindow !== false && !Ext.ux.plugin.VisibilityMode.MaxWinFixed){
        //Prevent overflow:hidden (reflow) transitions when an Ext.Window is maximize.
        CSS.updateRule ( '.x-window-maximized-ct', 'overflow', '');
        Ext.ux.plugin.VisibilityMode.MaxWinFixed = true;  //only updates the CSS Rule once.
    }

   };


  Ext.extend(Ext.ux.plugin.VisibilityMode , Object, {

       /**
        * @cfg {Boolean} bubble If true, the VisibilityMode fixes are also applied to parent Containers which may also impact DOM reflow.
        * @default true
        */
      bubble              :  true,

      /**
      * @cfg {Boolean} fixMaximizedWindow If not false, the ext-all.css style rule 'x-window-maximized-ct' is disabled to <b>prevent</b> reflow
      * after overflow:hidden is applied to the document.body.
      * @default true
      */
      fixMaximizedWindow  :  true,

      /**
       *
       * @cfg {array} elements (optional) A list of additional named component members to also adjust visibility for.
       * <br />By default, the plugin handles most scenarios automatically.
       * @default null
       * @example ['bwrap','toptoolbar']
       */

      elements       :  null,

      /**
       * @cfg {String} visibilityCls A specific CSS classname to apply to Component element when hidden/made visible.
       * @default 'x-hide-nosize'
       */

      visibilityCls   : 'x-hide-nosize',

      /**
       * @cfg {String} hideMode A specific hideMode value to assign to affected Components.
       * @default 'nosize'
       */
      hideMode  :   'nosize' ,

      ptype     :  'uxvismode',
      /**
      * Component plugin initialization method.
      * @param {Ext.Component} c The Ext.Component (or subclass) for which to apply visibilityMode treatment
      */
      init : function(c) {

        var hideMode = this.hideMode || c.hideMode,
            plugin = this,
            bubble = Ext.Container.prototype.bubble,
            changeVis = function(){

                var els = [this.collapseEl, this.actionMode].concat(plugin.elements||[]);

                Ext.each(els, function(el){
                    plugin.extend( this[el] || el );
                },this);

                var cfg = {
                    visFixed  : true,
                    animCollapse : false,
                    animFloat   : false,
                    hideMode  : hideMode,
                    defaults  : this.defaults || {}
                };

                cfg.defaults.hideMode = hideMode;

                Ext.apply(this, cfg);
                Ext.apply(this.initialConfig || {}, cfg);

            };

         c.on('render', function(){

            // Bubble up the layout and set the new
            // visibility mode on parent containers
            // which might also cause DOM reflow when
            // hidden or collapsed.
            if(plugin.bubble !== false && this.ownerCt){

               bubble.call(this.ownerCt, function(){
                  this.visFixed || this.on('afterlayout', changeVis, this, {single:true} );
               });
             }

             changeVis.call(this);

          }, c, {single:true});

     },
     /**
      * @param {Element/Array} el The Ext.Element (or Array of Elements) to extend visibilityCls handling to.
      * @param {String} visibilityCls The className to apply to the Element when hidden.
      * @return this
      */
     extend : function(el, visibilityCls){
        el && Ext.each([].concat(el), function(e){

            if(e && e.dom){
                 if('visibilityCls' in e)return;  //already applied or defined?
                 Ext.apply(e, fx.El);
                 e.visibilityCls = visibilityCls || this.visibilityCls;
            }
        },this);
        return this;
     }

  });

  Ext.preg && Ext.preg('uxvismode', Ext.ux.plugin.VisibilityMode );
  /** @sourceURL=<uxvismode.js> */
  Ext.provide && Ext.provide('uxvismode');
})();/* global Ext El ElFrame ELD*/
/*
 * ******************************************************************************
 * This file is distributed on an AS IS BASIS WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * ***********************************************************************************
 * License: multidom.js is offered under an MIT License.
 * Donations are welcomed: http://donate.theactivegroup.com
 */

 /**
  * @class multidom
  * @version 2.14
  * @license MIT
  * @author Doug Hendricks. Forum ID: <a href="http://extjs.com/forum/member.php?u=8730">hendricd</a>
  * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
  * @copyright 2007-2010, Active Group, Inc. All rights reserved.
  * @description [Designed For Ext Core and ExtJs Frameworks (using ext-base adapter only) 3.0 or higher ONLY]
  * The multidom library extends (overloads) Ext Core DOM methods and functions to
  * provide document-targeted access to the documents loaded in external (FRAME/IFRAME)
  * documents.
  * <p>It maintains seperate DOM Element caches (and more) for each document instance encountered by the
  * framework, permitting safe access to DOM Elements across document instances that may share
  * the same Element id or name.  In essence, multidom extends the functionality provided by Ext Core
  * into any child document without having to load the Core library into the frame's global context.
  * <h3>Custom Element classes.</h3>
  * The Ext.get method is enhanced to support resolution of the custom Ext.Element implementations.
  * (The ux.ManagedIFrame 2 Element class is an example of such a class.)
  * <p>For example: If you were retrieving the Ext.Element instance for an IFRAME and the class
  * Ext.Element.IFRAME were defined:
  * <pre><code>Ext.get('myFrame')</pre></code>
  * would return an instance of Ext.Element.IFRAME for 'myFrame' if it were found.
  * @example
   // return the Ext.Element with an id 'someDiv' located in external document hosted by 'iframe'
   var iframe = Ext.get('myFrame');
   var div = Ext.get('someDiv', iframe.getFrameDocument()); //Firefox example
   if(div){
     div.center();
    }
   Note: ux.ManagedIFrame provides an equivalent 'get' method of it's own to access embedded DOM Elements
   for the document it manages.
   <pre><code>iframe.get('someDiv').center();</pre></code>

   Likewise, you can retrieve the raw Element of another document with:
   var el = Ext.getDom('myDiv', iframe.getFrameDocument());
 */

 (function(){

    /*
     * Ext.Element and Ext.lib.DOM enhancements.
     * Primarily provides the ability to interact with any document context
     * (not just the one Ext was loaded into).
     */
   var El = Ext.Element,
       ElFrame,
       ELD = Ext.lib.Dom,
       A = Ext.lib.Anim,
       Evm = Ext.EventManager,
       E = Ext.lib.Event,
       DOC = document,
       emptyFn = function(){},
       OP = Object.prototype,
       OPString = OP.toString,
       bodyTag = /^body/i,
       HTMLDoc = '[object HTMLDocument]';
       
   if(!Ext.elCache || parseInt( Ext.version.replace(/\./g,''),10) < 311 ) {
    alert ('Ext Release '+Ext.version+' is not supported');
   }

   /**
    * @private
    */
   Ext._documents= {}; 
   Ext._documents[Ext.id(document,'_doc')]=Ext.elCache;

   /**
    * @private
    * Resolve the Element cache for a given element/window/document context.
    */
   var resolveCache = ELD.resolveDocumentCache = function(el, cacheId){
        
        /**
         * MUST re-assert Ext.elCache !! 
         * because of privately scoped references to Ext.elCache in the framework itself.
         */
        Ext._documents[Ext.id(document,'_doc')]=Ext.elCache;
        
        var doc = GETDOC(el),
            c = Ext.isDocument(doc) ? Ext.id(doc) : cacheId,
            cache = Ext._documents[c] || null;
         
         return cache || (c ? Ext._documents[c] = {}: null);
     },
     clearCache = ELD.clearDocumentCache = function(cacheId){
       delete  Ext._documents[cacheId];
     };

   El.addMethods || ( El.addMethods = function(ov){ Ext.apply(El.prototype, ov||{}); });
   
   Ext.removeNode =  function(n){
         var dom = n ? n.dom || n : null,
             el, elc, elCache = resolveCache(dom), parent;

            //clear out any references if found in the El.cache(s)
            if(dom && (elc = elCache[dom.id]) && (el = elc.el) ){
                if(el.dom){
                    Ext.enableNestedListenerRemoval ? Evm.purgeElement(el.dom, true) : Evm.removeAll(el.dom);
                }
                delete elCache[dom.id];
                delete el.dom;
                delete el._context;
                el = null;
            }
            //No removal for window, documents, or bodies
            if(dom && !dom.navigator && !Ext.isDocument(dom) && !bodyTag.test(dom.tagName)){
                (parent = dom.parentElement || dom.parentNode) && parent.removeChild(dom);
            }
            dom = parent = null;
    };

    var overload = function(pfn, fn ){
           var f = typeof pfn === 'function' ? pfn : function t(){};
           var ov = f._ovl; //call signature hash
           if(!ov){
               ov = { base: f};
               ov[f.length|| 0] = f;
               f= function t(){  //the proxy stub
                  var o = arguments.callee._ovl;
                  var fn = o[arguments.length] || o.base;
                  //recursion safety
                  return fn && fn != arguments.callee ? fn.apply(this,arguments): undefined;
               };
           }
           var fnA = [].concat(fn);
           for(var i=0,l=fnA.length; i<l; ++i){
             //ensures no duplicate call signatures, but last in rules!
             ov[fnA[i].length] = fnA[i];
           }
           f._ovl= ov;
           var t = null;
           return f;
       };

    Ext.applyIf( Ext, {
        overload : overload( overload,
           [
             function(fn){ return overload(null, fn);},
             function(obj, mname, fn){
                 return obj[mname] = overload(obj[mname],fn);}
          ]),

        isArray : function(v){
           return !!v && OPString.apply(v) == '[object Array]';
        },

        isObject:function(obj){
            return !!obj && typeof obj == 'object';
        },

        /**
         * HTMLDocument assertion with optional accessibility testing
         * @param {HTMLELement} el The DOM Element to test
         * @param {Boolean} testOrigin (optional) True to test "same-origin" access
         *
         */
        isDocument : function(el, testOrigin){
            var elm = el ? el.dom || el : null;
            var test = elm && ((OPString.apply(elm) == HTMLDoc) || (elm && elm.nodeType == 9));
            if(test && testOrigin){
                try{
                    test = !!elm.location;
                }
                catch(e){return false;}
            }
            return test;
        },

        isWindow : function(el){
          var elm = el ? el.dom || el : null;
          return elm ? !!elm.navigator || OPString.apply(elm) == "[object Window]" : false;
        },

        isIterable : function(v){
            //check for array or arguments
            if(Ext.isArray(v) || v.callee){
                return true;
            }
            //check for node list type
            if(/NodeList|HTMLCollection/.test(OPString.call(v))){
                return true;
            }
            //NodeList has an item and length property
            //IXMLDOMNodeList has nextNode method, needs to be checked first.
            return ((typeof v.nextNode != 'undefined' || v.item) && Ext.isNumber(v.length));
  
        },
        isElement : function(obj){
            return obj && Ext.type(obj)== 'element';
        },

        isEvent : function(obj){
            return OPString.apply(obj) == '[object Event]' || (Ext.isObject(obj) && !Ext.type(o.constructor) && (window.event && obj.clientX && obj.clientX == window.event.clientX));
        },

        isFunction: function(obj){
            return !!obj && typeof obj == 'function';
        },

        /**
         * Determine whether a specified DOMEvent is supported by a given HTMLElement or Object.
         * @param {String} type The eventName (without the 'on' prefix)
         * @param {HTMLElement/Object/String} testEl (optional) A specific HTMLElement/Object to test against, otherwise a tagName to test against.
         * based on the passed eventName is used, or DIV as default.
         * @return {Boolean} True if the passed object supports the named event.
         */
        isEventSupported : function(evName, testEl){
             var TAGNAMES = {
                  'select':'input',
                  'change':'input',
                  'submit':'form',
                  'reset':'form',
                  'load':'img',
                  'error':'img',
                  'abort':'img'
                },
                //Cached results
                cache = {},
                onPrefix = /^on/i,
                //Get a tokenized string of the form nodeName:type
                getKey = function(type, el){
                    var tEl = Ext.getDom(el);
                    return (tEl ?
                           (Ext.isElement(tEl) || Ext.isDocument(tEl) ?
                                tEl.nodeName.toLowerCase() :
                                    el.self ? '#window' : el || '#object')
                       : el || 'div') + ':' + type;
                };

            return function (evName, testEl) {
              evName = (evName || '').replace(onPrefix,'');
              var el, isSupported = false;
              var eventName = 'on' + evName;
              var tag = (testEl ? testEl : TAGNAMES[evName]) || 'div';
              var key = getKey(evName, tag);

              if(key in cache){
                //Use a previously cached result if available
                return cache[key];
              }

              el = Ext.isString(tag) ? DOC.createElement(tag): testEl;
              isSupported = (!!el && (eventName in el));

              isSupported || (isSupported = window.Event && !!(String(evName).toUpperCase() in window.Event));

              if (!isSupported && el) {
                el.setAttribute && el.setAttribute(eventName, 'return;');
                isSupported = Ext.isFunction(el[eventName]);
              }
              //save the cached result for future tests
              cache[key] = isSupported;
              el = null;
              return isSupported;
            };

        }()
    });


    /**
     * @private
     * Determine Ext.Element[tagName] or Ext.Element (default)
     */
    var assertClass = function(el){
    	
    	return El;
        return El[(el.tagName || '-').toUpperCase()] || El;

      };

    var libFlyweight;
    function fly(el, doc) {
        if (!libFlyweight) {
            libFlyweight = new Ext.Element.Flyweight();
        }
        libFlyweight.dom = Ext.getDom(el, null, doc);
        return libFlyweight;
    }


    Ext.apply(Ext, {
    /*
     * Overload Ext.get to permit Ext.Element access to other document objects
     * This implementation maintains safe element caches for each document queried.
     *
     */

      get : El.get = function(el, doc){         //document targeted
            if(!el ){ return null; }
            var isDoc = Ext.isDocument(el); 
            
            Ext.isDocument(doc) || (doc = DOC);
            
            var ex, elm, id, cache = resolveCache(doc);
            if(typeof el == "string"){ // element id
                elm = Ext.getDom(el, null, doc);
                if(!elm) return null;
                if(cache[el] && cache[el].el){
                    ex = cache[el].el;
                    ex.dom = elm;
                }else{
                    ex = El.addToCache(new (assertClass(elm))(elm, null, doc));
                }
                return ex;
            
            }else if(isDoc){

                if(!Ext.isDocument(el, true)){ return false; }  //is it accessible
                cache = resolveCache(el);

                if(cache[Ext.id(el)] && cache[el.id].el){
                    return cache[el.id].el;
                }
                // create a bogus element object representing the document object
                var f = function(){};
                f.prototype = El.prototype;
                var docEl = new f();
                docEl.dom = el;
                docEl.id = Ext.id(el,'_doc');
                docEl._isDoc = true;
                El.addToCache( docEl, null, cache);
                return docEl;
                        
             }else if( el instanceof El ){ 
                
                // refresh dom element in case no longer valid,
                // catch case where it hasn't been appended
                 
                if(el.dom){
                    el.id = Ext.id(el.dom);
                }else{
                    el.dom = el.id ? Ext.getDom(el.id, true) : null;
                }
                if(el.dom){
	                cache = resolveCache(el);
	                (cache[el.id] || 
	                       (cache[el.id] = {data : {}, events : {}}
	                       )).el = el; // in case it was created directly with Element(), let's cache it
                }
                return el;
                
            }else if(el.tagName || Ext.isWindow(el)){ // dom element
                cache = resolveCache(el);
                id = Ext.id(el);
                if(cache[id] && (ex = cache[id].el)){
                    ex.dom = el;
                }else{
                    ex = El.addToCache(new (assertClass(el))(el, null, doc), null, cache); 
                }
                return ex;

            }else if(el.isComposite){
                return el;

            }else if(Ext.isArray(el)){
                return Ext.get(doc,doc).select(el);
            }
           return null;

    },

     /**
      * Ext.getDom to support targeted document contexts
      */
     getDom : function(el, strict, doc){
        var D = doc || DOC;
        if(!el || !D){
            return null;
        }
        if (el.dom){
            return el.dom;
        } else {
            if (Ext.isString(el)) {
                var e = D.getElementById(el);
                // IE returns elements with the 'name' and 'id' attribute.
                // we do a strict check to return the element with only the id attribute
                if (e && Ext.isIE && strict) {
                    if (el == e.getAttribute('id')) {
                        return e;
                    } else {
                        return null;
                    }
                }
                return e;
            } else {
                return el;
            }
        }
            
     },
     /**
     * Returns the current/specified document body as an {@link Ext.Element}.
     * @param {HTMLDocument} doc (optional)
     * @return Ext.Element The document's body
     */
     getBody : function(doc){
            var D = ELD.getDocument(doc) || DOC;
            return Ext.get(D.body || D.documentElement);
       },

     getDoc :Ext.overload([
       Ext.getDoc,
       function(doc){ return Ext.get(doc,doc); }
       ])
   });

   // private method for getting and setting element data
    El.data = function(el, key, value){
        el = El.get(el);
        if (!el) {
            return null;
        }
        var c = resolveCache(el)[el.id].data;
        if(arguments.length == 2){
            return c[key];
        }else{
            return (c[key] = value);
        }
    };
    
    El.addToCache = function(el, id, cache ){
        id = id || Ext.id(el);
        var C = cache || resolveCache(el);
        C[id] = {
            el:  el.dom ? el : Ext.get(el),
            data: {},
            events: {}
        };
        var d = C[id].el.dom;
        (d.getElementById || d.navigator) && (C[id].skipGC = true);
        return C[id].el;
    };
    
    El.removeFromCache = function(el, cache){
        if(el && el.id){
            var C = cache || resolveCache(el);
            delete C[el.id];
        }
    };
    
    /*
     * Add new Visibility Mode to element (sets height and width to 0px instead of display:none )
     */
    El.OFFSETS = 3;
    El.ASCLASS = 4;
    
    El.visibilityCls = 'x-hide-nosize';

    var propCache = {},
        camelRe = /(-[a-z])/gi,
        camelFn = function(m, a){ return a.charAt(1).toUpperCase(); },
        opacityRe = /alpha\(opacity=(.*)\)/i,
        trimRe = /^\s+|\s+$/g,
        marginRightRe = /marginRight/,
        propFloat = Ext.isIE ? 'styleFloat' : 'cssFloat',
        view = DOC.defaultView,
        VISMODE = 'visibilityMode',
        ASCLASS  = "asclass",
        ORIGINALDISPLAY = 'originalDisplay',
        PADDING = "padding",
        MARGIN = "margin",
        BORDER = "border",
        LEFT = "-left",
        RIGHT = "-right",
        TOP = "-top",
        BOTTOM = "-bottom",
        WIDTH = "-width",
        MATH = Math,
        OPACITY = "opacity",
        VISIBILITY = "visibility",
        DISPLAY = "display",
        OFFSETS = "offsets",
        NOSIZE = 'nosize',
        ASCLASS  = "asclass",
        HIDDEN = "hidden",
        NONE = "none", 
        ISVISIBLE = 'isVisible',
        ISCLIPPED = 'isClipped',
        OVERFLOW = 'overflow',
        OVERFLOWX = 'overflow-x',
        OVERFLOWY = 'overflow-y',
        ORIGINALCLIP = 'originalClip',
        XMASKED = "x-masked",
        XMASKEDRELATIVE = "x-masked-relative",
        // special markup used throughout Ext when box wrapping elements
        borders = {l: BORDER + LEFT + WIDTH, r: BORDER + RIGHT + WIDTH, t: BORDER + TOP + WIDTH, b: BORDER + BOTTOM + WIDTH},
        paddings = {l: PADDING + LEFT, r: PADDING + RIGHT, t: PADDING + TOP, b: PADDING + BOTTOM},
        margins = {l: MARGIN + LEFT, r: MARGIN + RIGHT, t: MARGIN + TOP, b: MARGIN + BOTTOM},
        data = El.data,
        GETDOM = Ext.getDom,
        GET = Ext.get,
        DH = Ext.DomHelper,
        propRe = /^(?:scope|delay|buffer|single|stopEvent|preventDefault|stopPropagation|normalized|args|delegate)$/,
        CSS = Ext.util.CSS,  //Not available in Ext Core.
        getDisplay = function(dom){
            var d = data(dom, ORIGINALDISPLAY);
            if(d === undefined){
                data(dom, ORIGINALDISPLAY, d = '');
            }
            return d;
        },
        getVisMode = function(dom){
            var m = data(dom, VISMODE);
            if(m === undefined){
                data(dom, VISMODE, m = El.prototype.visibilityMode)
            }
            return m;
        };

    function chkCache(prop) {
        return propCache[prop] || (propCache[prop] = prop == 'float' ? propFloat : prop.replace(camelRe, camelFn));
    };


    El.addMethods({
        /**
         * Resolves the current document context of this Element
         */
        getDocument : function(){
           return this._context || (this._context = GETDOC(this));
        },

        /**
      * Removes this element from the DOM and deletes it from the cache
      * @param {Boolean} cleanse (optional) Perform a cleanse of immediate childNodes as well.
      * @param {Boolean} deep (optional) Perform a deep cleanse of all nested childNodes as well.
      */

        remove : function(cleanse, deep){
            
          var dom = this.dom;
          //this.isMasked() && this.unmask();
          if(dom){
            Ext.removeNode(dom);
            delete this._context;
            delete this.dom;
          }
        },

         /**
         * Appends the passed element(s) to this element
         * @param {String/HTMLElement/Array/Element/CompositeElement} el
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        appendChild: function(el, doc){
            return GET(el, doc || this.getDocument()).appendTo(this);
        },

        /**
         * Appends this element to the passed element
         * @param {Mixed} el The new parent element
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        appendTo: function(el, doc){
            GETDOM(el, false, doc || this.getDocument()).appendChild(this.dom);
            return this;
        },

        /**
         * Inserts this element before the passed element in the DOM
         * @param {Mixed} el The element before which this element will be inserted
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        insertBefore: function(el, doc){
            (el = GETDOM(el, false, doc || this.getDocument())).parentNode.insertBefore(this.dom, el);
            return this;
        },

        /**
         * Inserts this element after the passed element in the DOM
         * @param {Mixed} el The element to insert after
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        insertAfter: function(el, doc){
            (el = GETDOM(el, false, doc || this.getDocument())).parentNode.insertBefore(this.dom, el.nextSibling);
            return this;
        },

        /**
         * Inserts (or creates) an element (or DomHelper config) as the first child of this element
         * @param {Mixed/Object} el The id or element to insert or a DomHelper config to create and insert
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} The new child
         */
        insertFirst: function(el, returnDom){
            el = el || {};
            if(el.nodeType || el.dom || typeof el == 'string'){ // element
                el = GETDOM(el);
                this.dom.insertBefore(el, this.dom.firstChild);
                return !returnDom ? GET(el) : el;
            }else{ // dh config
                return this.createChild(el, this.dom.firstChild, returnDom);
            }
        },

        /**
         * Replaces the passed element with this element
         * @param {Mixed} el The element to replace
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        replace: function(el, doc){
            el = GET(el, doc || this.getDocument());
            this.insertBefore(el);
            el.remove();
            return this;
        },

        /**
         * Replaces this element with the passed element
         * @param {Mixed/Object} el The new element or a DomHelper config of an element to create
         * @param {Document} doc (optional) specific document context for the Element search
         * @return {Ext.Element} this
         */
        replaceWith: function(el, doc){
            var me = this;
            if(el.nodeType || el.dom || typeof el == 'string'){
                el = GETDOM(el, false, doc || me.getDocument());
                me.dom.parentNode.insertBefore(el, me.dom);
            }else{
                el = DH.insertBefore(me.dom, el);
            }
            var C = resolveCache(me);
            Ext.removeNode(me.dom);
            me.id = Ext.id(me.dom = el);

            El.addToCache(me.isFlyweight ? new (assertClass(me.dom))(me.dom, null, C) : me);     
            return me;
        },


        /**
         * Inserts an html fragment into this element
         * @param {String} where Where to insert the html in relation to this element - beforeBegin, afterBegin, beforeEnd, afterEnd.
         * @param {String} html The HTML fragment
         * @param {Boolean} returnEl (optional) True to return an Ext.Element (defaults to false)
         * @return {HTMLElement/Ext.Element} The inserted node (or nearest related if more than 1 inserted)
         */
        insertHtml : function(where, html, returnEl){
            var el = DH.insertHtml(where, this.dom, html);
            return returnEl ? Ext.get(el, GETDOC(el)) : el;
        },
             
        
        /**
         * Checks whether the element is currently visible using both visibility and display properties.
         * @return {Boolean} True if the element is currently visible, else false
         */
        isVisible : function(deep) {
            var me=this,
                dom = me.dom,
                p = dom.parentNode,
                visible = data(dom, ISVISIBLE);  //use the cached value if registered
               
            if(typeof visible != 'boolean'){ 
               
	            //Determine the initial state based on display states
	            visible = !me.hasClass(me.visibilityCls || El.visibilityCls) && 
	                      !me.isStyle(VISIBILITY, HIDDEN) && 
	                      !me.isStyle(DISPLAY, NONE); 
	                      
	            data(dom, ISVISIBLE, visible);
            }
            
                
            if(deep !== true || !visible){
                return visible;
            }
            while(p && !bodyTag.test(p.tagName)){
                if(!Ext.fly(p, '_isVisible').isVisible()){
                    return false;
                }
                p = p.parentNode;
            }
            return true;
            
        },
                
        /**
         * Sets the visibility of the element (see details). If the visibilityMode is set to Element.DISPLAY, it will use
         * the display property to hide the element, otherwise it uses visibility. The default is to hide and show using the visibility property.
         * @param {Boolean} visible Whether the element is visible
         * @param {Boolean/Object} animate (optional) True for the default animation, or a standard Element animation config object, or one of four
         *         possible hideMode strings: 'display, visibility, offsets, asclass'
         * @return {Ext.Element} this
         */
        setVisible : function(visible, animate){
            var me = this, 
                dom = me.dom,
                visMode = getVisMode(dom);
           
            // hideMode string override
            if (typeof animate == 'string'){
                switch (animate) {
                    case DISPLAY:
                        visMode = El.DISPLAY;
                        break;
                    case VISIBILITY:
                        visMode = El.VISIBILITY;
                        break;
                    case OFFSETS:
                        visMode = El.OFFSETS;
                        break;
                    case NOSIZE:
                    case ASCLASS:
                        visMode = El.ASCLASS;
                        break;
                }
                me.setVisibilityMode(visMode);
                animate = false;
            }
             
            if (!animate || !me.anim) {
                if(visMode == El.ASCLASS ){
                    
                    me[visible?'removeClass':'addClass'](me.visibilityCls || El.visibilityCls);
                    
                } else if (visMode == El.DISPLAY){
                    
                    return me.setDisplayed(visible);
                    
                } else if (visMode == El.OFFSETS){
                    
                    if (!visible){
                        me.hideModeStyles = {
                            position: me.getStyle('position'),
                            top: me.getStyle('top'),
                            left: me.getStyle('left')
                        };
                        me.applyStyles({position: 'absolute', top: '-10000px', left: '-10000px'});
                    } else {
                        me.applyStyles(me.hideModeStyles || {position: '', top: '', left: ''});
                        delete me.hideModeStyles;
                    }
                
                }else{
                    me.fixDisplay();
                    dom.style.visibility = visible ? "visible" : HIDDEN;
                }
            }else{
                // closure for composites            
                if(visible){
                    me.setOpacity(.01);
                    me.setVisible(true);
                }
                me.anim({opacity: { to: (visible?1:0) }},
                        me.preanim(arguments, 1),
                        null,
                        .35,
                        'easeIn',
                        function(){
                            visible || me.setVisible(false).setOpacity(1);
                        });
            }
            data(dom, ISVISIBLE, visible);  //set logical visibility state
            return me;
        },
        
        hasMetrics  : function(){
            var me = this;
            return me.isVisible() || (getVisMode(me.dom) == El.VISIBILITY);     
        },
        /**
         * Sets the CSS display property. Uses originalDisplay if the specified value is a boolean true.
         * @param {Mixed} value Boolean value to display the element using its default display, or a string to set the display directly.
         * @return {Ext.Element} this
         */
        setDisplayed : function(value) {
            var dom = this.dom,
                visMode = getVisMode(dom);
            
            if(typeof value == "boolean"){
               
               if(visMode == El.ASCLASS){
                  return this.setVisible(value);
               }
               data(this.dom, ISVISIBLE, value);
               value = value ? getDisplay(dom) : NONE;
            }
            this.setStyle(DISPLAY, value);
            return this;
        },
        
                
        /**
         * Convenience method for setVisibilityMode(Element.DISPLAY)
         * @param {String} display (optional) What to set display to when visible
         * @return {Ext.Element} this
         */
        enableDisplayMode : function(display){      
            this.setVisibilityMode(El.DISPLAY);
            if(!Ext.isEmpty(display)){
                data(this.dom, ORIGINALDISPLAY, display);
            }
            return this;
        },
        
        
        scrollIntoView : function(container, hscroll){
                var d = this.getDocument(),
                    c = Ext.getDom(container, null, d) || Ext.getBody(d).dom,
                    el = this.dom,
                    o = this.getOffsetsTo(c),
                    l = o[0] + c.scrollLeft,
		            t = o[1] + c.scrollTop,
		            b = t + el.offsetHeight,
		            r = l + el.offsetWidth,
		            ch = c.clientHeight,
		            ct = parseInt(c.scrollTop, 10),
		            cl = parseInt(c.scrollLeft, 10),
		            cb = ct + ch,
		            cr = cl + c.clientWidth;
                    
                if(el.offsetHeight > ch || t < ct){
                    c.scrollTop = t;
                }else if(b > cb){
                    c.scrollTop = b-ch;
                }
                // corrects IE, other browsers will ignore
                c.scrollTop = c.scrollTop; 
                if(hscroll !== false){
                    if(el.offsetWidth > c.clientWidth || l < cl){
                        c.scrollLeft = l;
                    }else if(r > cr){
                        c.scrollLeft = r-c.clientWidth;
                    }
                    c.scrollLeft = c.scrollLeft;
                }
                return this;
        },

        contains : function(el){
            try {
                return !el ? false : ELD.isAncestor(this.dom, el.dom ? el.dom : el);
            } catch(e) {
                return false;
            }
        },

        /**
         * Returns the current scroll position of the element.
         * @return {Object} An object containing the scroll position in the format {left: (scrollLeft), top: (scrollTop)}
         */
        getScroll : function(){
            var d = this.dom,
            doc = this.getDocument(),
            body = doc.body,
            docElement = doc.documentElement,
            l,
            t,
            ret;

            if(Ext.isDocument(d) || d == body){
                if(Ext.isIE && ELD.docIsStrict(doc)){
                    l = docElement.scrollLeft;
                    t = docElement.scrollTop;
                }else{
                    l = window.pageXOffset;
                    t = window.pageYOffset;
                }
                ret = {left: l || (body ? body.scrollLeft : 0), top: t || (body ? body.scrollTop : 0)};
            }else{
                ret = {left: d.scrollLeft, top: d.scrollTop};
            }
            return ret;
        },
        /**
         * Normalizes currentStyle and computedStyle.
         * @param {String} property The style property whose value is returned.
         * @return {String} The current value of the style property for this element.
         */
        getStyle : function(){
            var getStyle =
             view && view.getComputedStyle ?
                function GS(prop){
                    var el = !this._isDoc ? this.dom : null,
                        v,
                        cs,
                        out,
                        display,
                        wk = Ext.isWebKit,
                        display,
                        style;

                    if(!el || !el.style) return null;
                    style = el.style;
                    prop = chkCache(prop);
                    cs = view.getComputedStyle(el, null);
                    out = (cs) ? cs[prop]: null;
                           
                    // Fix bug caused by this: https://bugs.webkit.org/show_bug.cgi?id=13343
                    if(wk){
                        if(out && marginRightRe.test(prop) &&
                            style.position != 'absolute' && 
                            out != '0px'){
		                        display = style.display;
		                        style.display = 'inline-block';
		                        out = view.getComputedStyle(el, null)[prop];
		                        style.display = display;
	                    }else if(out == 'rgba(0, 0, 0, 0)'){
                            //Webkit returns rgb values for transparent.
	                        out = 'transparent';
	                    }
                    }
                    return out || style[prop];
                } :
                function GS(prop){ //IE < 9
                   var el = !this._isDoc ? this.dom : null,
                        m,
                        cs,
                        style;
                    if(!el || !el.style) return null;
                    style = el.style;
                    if (prop == OPACITY ) {
                        if (style.filter.match) {
                            if(m = style.filter.match(opacityRe)){
                                var fv = parseFloat(m[1]);
                                if(!isNaN(fv)){
                                    return fv ? fv / 100 : 0;
                                }
                            }
                        }
                        return 1;
                    }
                    prop = chkCache(prop);
                    return ((cs = el.currentStyle) ? cs[prop] : null) || el.style[prop];
                };
                var GS = null;
                return getStyle;
        }(),
        /**
         * Wrapper for setting style properties, also takes single object parameter of multiple styles.
         * @param {String/Object} property The style property to be set, or an object of multiple styles.
         * @param {String} value (optional) The value to apply to the given property, or null if an object was passed.
         * @return {Ext.Element} this
         */
        setStyle : function(prop, value){
            if(this._isDoc || Ext.isDocument(this.dom)) return this;
            var tmp, style;
                
            if (typeof prop != 'object') {
                tmp = {};
                tmp[prop] = value;
                prop = tmp;
            }
            for (style in prop) {
                if(prop.hasOwnProperty(style)) {
                    value = prop[style];
	                style == OPACITY ?
	                    this.setOpacity(value) :
	                    this.dom.style[chkCache(style)] = value;
                }
            }
            return this;
        },
        /**
        * Centers the Element in either the viewport, or another Element.
        * @param {Mixed} centerIn (optional) The element in which to center the element.
        */
        center : function(centerIn){
            return this.alignTo(centerIn || this.getDocument(), 'c-c');
        },
        
        /**
         * Puts a mask over this element to disable user interaction. Requires core.css.
         * This method can only be applied to elements which accept child nodes.
         * @param {String} msg (optional) A message to display in the mask
         * @param {String} msgCls (optional) A css class to apply to the msg element
         * @return {Element} The mask element
         */
        mask : function(msg, msgCls){
            var me = this,
                dom = me.dom,
                dh = Ext.DomHelper,
                EXTELMASKMSG = "ext-el-mask-msg",
                el, 
                mask;
                
            if(me.getStyle("position") == "static"){
                me.addClass(XMASKEDRELATIVE);
            }
            if((el = data(dom, 'maskMsg'))){
                el.remove();
            }
            if((el = data(dom, 'mask'))){
                el.remove();
            }
    
            mask = dh.append(dom, {cls : "ext-el-mask"}, true);
            data(dom, 'mask', mask);
    
            me.addClass(XMASKED);
            mask.setDisplayed(true);
            if(typeof msg == 'string'){
                var mm = dh.append(dom, {cls : EXTELMASKMSG, cn:{tag:'div'}}, true);
                data(dom, 'maskMsg', mm);
                mm.dom.className = msgCls ? EXTELMASKMSG + " " + msgCls : EXTELMASKMSG;
                mm.dom.firstChild.innerHTML = msg;
                mm.setDisplayed(true);
                mm.center(me);
            }
            if(Ext.isIE && !(Ext.isIE7 && Ext.isStrict) && me.getStyle('height') == 'auto'){ // ie will not expand full height automatically
                mask.setSize(undefined, me.getHeight());
            }
            return mask;
        },
    
        /**
         * Removes a previously applied mask.
         */
        unmask : function(){
            var me = this,
                dom = me.dom,
                mask = data(dom, 'mask'),
                maskMsg = data(dom, 'maskMsg');
            if(mask){
                if(maskMsg){
                    maskMsg.remove();
                    data(dom, 'maskMsg', undefined);
                }
                mask.remove();
                data(dom, 'mask', undefined);
            }
            me.removeClass([XMASKED, XMASKEDRELATIVE]);
        },
        
        /**
         * Returns true if this element is masked
         * @return {Boolean}
         */
        isMasked : function(){
            var m = data(this.dom, 'mask');
            return m && m.isVisible();
        },

        /**
        * Calculates the x, y to center this element on the screen
        * @return {Array} The x, y values [x, y]
        */
        getCenterXY : function(){
            return this.getAlignToXY(this.getDocument(), 'c-c');
        },
        /**
         * Gets the x,y coordinates specified by the anchor position on the element.
         * @param {String} anchor (optional) The specified anchor position (defaults to "c").  See {@link #alignTo}
         * for details on supported anchor positions.
         * @param {Boolean} local (optional) True to get the local (element top/left-relative) anchor position instead
         * of page coordinates
         * @param {Object} size (optional) An object containing the size to use for calculating anchor position
         * {width: (target width), height: (target height)} (defaults to the element's current size)
         * @return {Array} [x, y] An array containing the element's x and y coordinates
         */
        getAnchorXY : function(anchor, local, s){
            //Passing a different size is useful for pre-calculating anchors,
            //especially for anchored animations that change the el size.
            anchor = (anchor || "tl").toLowerCase();
            s = s || {};

            var me = this,  doc = this.getDocument(),
                vp = me.dom == doc.body || me.dom == doc,
                w = s.width || vp ? ELD.getViewWidth(false,doc) : me.getWidth(),
                h = s.height || vp ? ELD.getViewHeight(false,doc) : me.getHeight(),
                xy,
                r = Math.round,
                o = me.getXY(),
                scroll = me.getScroll(),
                extraX = vp ? scroll.left : !local ? o[0] : 0,
                extraY = vp ? scroll.top : !local ? o[1] : 0,
                hash = {
                    c  : [r(w * .5), r(h * .5)],
                    t  : [r(w * .5), 0],
                    l  : [0, r(h * .5)],
                    r  : [w, r(h * .5)],
                    b  : [r(w * .5), h],
                    tl : [0, 0],
                    bl : [0, h],
                    br : [w, h],
                    tr : [w, 0]
                };

            xy = hash[anchor];
            return [xy[0] + extraX, xy[1] + extraY];
        },

        /**
         * Anchors an element to another element and realigns it when the window is resized.
         * @param {Mixed} element The element to align to.
         * @param {String} position The position to align to.
         * @param {Array} offsets (optional) Offset the positioning by [x, y]
         * @param {Boolean/Object} animate (optional) True for the default animation or a standard Element animation config object
         * @param {Boolean/Number} monitorScroll (optional) True to monitor body scroll and reposition. If this parameter
         * is a number, it is used as the buffer delay (defaults to 50ms).
         * @param {Function} callback The function to call after the animation finishes
         * @return {Ext.Element} this
         */
        anchorTo : function(el, alignment, offsets, animate, monitorScroll, callback){
            var me = this,
                dom = me.dom;

            function action(){
                fly(dom).alignTo(el, alignment, offsets, animate);
                Ext.callback(callback, fly(dom));
            };

            Ext.EventManager.onWindowResize(action, me);

            if(!Ext.isEmpty(monitorScroll)){
                Ext.EventManager.on(window, 'scroll', action, me,
                    {buffer: !isNaN(monitorScroll) ? monitorScroll : 50});
            }
            action.call(me); // align immediately
            return me;
        },

        /**
         * Returns the current scroll position of the element.
         * @return {Object} An object containing the scroll position in the format {left: (scrollLeft), top: (scrollTop)}
         */
        getScroll : function(){
            var d = this.dom,
                doc = this.getDocument(),
                body = doc.body,
                docElement = doc.documentElement,
                l,
                t,
                ret;

            if(d == doc || d == body){
                if(Ext.isIE && ELD.docIsStrict(doc)){
                    l = docElement.scrollLeft;
                    t = docElement.scrollTop;
                }else{
                    l = window.pageXOffset;
                    t = window.pageYOffset;
                }
                ret = {left: l || (body ? body.scrollLeft : 0), top: t || (body ? body.scrollTop : 0)};
            }else{
                ret = {left: d.scrollLeft, top: d.scrollTop};
            }
            return ret;
        },

        /**
         * Gets the x,y coordinates to align this element with another element. See {@link #alignTo} for more info on the
         * supported position values.
         * @param {Mixed} element The element to align to.
         * @param {String} position The position to align to.
         * @param {Array} offsets (optional) Offset the positioning by [x, y]
         * @return {Array} [x, y]
         */
        getAlignToXY : function(el, p, o){
            var doc;
            el = Ext.get(el, doc = this.getDocument());

            if(!el || !el.dom){
                throw "Element.getAlignToXY with an element that doesn't exist";
            }

            o = o || [0,0];
            p = (p == "?" ? "tl-bl?" : (!/-/.test(p) && p != "" ? "tl-" + p : p || "tl-bl")).toLowerCase();

            var me = this,
                d = me.dom,
                a1,
                a2,
                x,
                y,
                //constrain the aligned el to viewport if necessary
                w,
                h,
                r,
                dw = ELD.getViewWidth(false,doc) -10, // 10px of margin for ie
                dh = ELD.getViewHeight(false,doc)-10, // 10px of margin for ie
                p1y,
                p1x,
                p2y,
                p2x,
                swapY,
                swapX,
                docElement = doc.documentElement,
                docBody = doc.body,
                scrollX = (docElement.scrollLeft || docBody.scrollLeft || 0)+5,
                scrollY = (docElement.scrollTop || docBody.scrollTop || 0)+5,
                c = false, //constrain to viewport
                p1 = "",
                p2 = "",
                m = p.match(/^([a-z]+)-([a-z]+)(\?)?$/);

            if(!m){
               throw "Element.getAlignToXY with an invalid alignment " + p;
            }

            p1 = m[1];
            p2 = m[2];
            c = !!m[3];

            //Subtract the aligned el's internal xy from the target's offset xy
            //plus custom offset to get the aligned el's new offset xy
            a1 = me.getAnchorXY(p1, true);
            a2 = el.getAnchorXY(p2, false);

            x = a2[0] - a1[0] + o[0];
            y = a2[1] - a1[1] + o[1];

            if(c){
               w = me.getWidth();
               h = me.getHeight();
               r = el.getRegion();
               //If we are at a viewport boundary and the aligned el is anchored on a target border that is
               //perpendicular to the vp border, allow the aligned el to slide on that border,
               //otherwise swap the aligned el to the opposite border of the target.
               p1y = p1.charAt(0);
               p1x = p1.charAt(p1.length-1);
               p2y = p2.charAt(0);
               p2x = p2.charAt(p2.length-1);
               swapY = ((p1y=="t" && p2y=="b") || (p1y=="b" && p2y=="t"));
               swapX = ((p1x=="r" && p2x=="l") || (p1x=="l" && p2x=="r"));


               if (x + w > dw + scrollX) {
                    x = swapX ? r.left-w : dw+scrollX-w;
               }
               if (x < scrollX) {
                   x = swapX ? r.right : scrollX;
               }
               if (y + h > dh + scrollY) {
                    y = swapY ? r.top-h : dh+scrollY-h;
                }
               if (y < scrollY){
                   y = swapY ? r.bottom : scrollY;
               }
            }

            return [x,y];
        },
            // private ==>  used outside of core
        adjustForConstraints : function(xy, parent, offsets){
            return this.getConstrainToXY(parent || this.getDocument(), false, offsets, xy) ||  xy;
        },

        // private ==>  used outside of core
        getConstrainToXY : function(el, local, offsets, proposedXY){
            var os = {top:0, left:0, bottom:0, right: 0};

            return function(el, local, offsets, proposedXY){
                var doc = this.getDocument();
                el = Ext.get(el, doc);
                offsets = offsets ? Ext.applyIf(offsets, os) : os;

                var vw, vh, vx = 0, vy = 0;
                if(el.dom == doc.body || el.dom == doc){
                    vw = ELD.getViewWidth(false,doc);
                    vh = ELD.getViewHeight(false,doc);
                }else{
                    vw = el.dom.clientWidth;
                    vh = el.dom.clientHeight;
                    if(!local){
                        var vxy = el.getXY();
                        vx = vxy[0];
                        vy = vxy[1];
                    }
                }

                var s = el.getScroll();

                vx += offsets.left + s.left;
                vy += offsets.top + s.top;

                vw -= offsets.right;
                vh -= offsets.bottom;

                var vr = vx + vw,
                    vb = vy + vh,
                    xy = proposedXY || (!local ? this.getXY() : [this.getLeft(true), this.getTop(true)]);
                    x = xy[0], y = xy[1],
                    offset = this.getConstrainOffset(),
                    w = this.dom.offsetWidth + offset, 
                    h = this.dom.offsetHeight + offset;

                // only move it if it needs it
                var moved = false;

                // first validate right/bottom
                if((x + w) > vr){
                    x = vr - w;
                    moved = true;
                }
                if((y + h) > vb){
                    y = vb - h;
                    moved = true;
                }
                // then make sure top/left isn't negative
                if(x < vx){
                    x = vx;
                    moved = true;
                }
                if(y < vy){
                    y = vy;
                    moved = true;
                }
                return moved ? [x, y] : false;
            };
        }(),
        
        // private, used internally
	    getConstrainOffset : function(){
	        return 0;
	    },
	    
        /**
        * Calculates the x, y to center this element on the screen
        * @return {Array} The x, y values [x, y]
        */
        getCenterXY : function(){
            return this.getAlignToXY(Ext.getBody(this.getDocument()), 'c-c');
        },
       
        /**
        * Centers the Element in either the viewport, or another Element.
        * @param {Mixed} centerIn (optional) The element in which to center the element.
        */
        center : function(centerIn){
            return this.alignTo(centerIn || Ext.getBody(this.getDocument()), 'c-c');
        } ,

        /**
         * Looks at this node and then at parent nodes for a match of the passed simple selector (e.g. div.some-class or span:first-child)
         * @param {String} selector The simple selector to test
         * @param {Number/Mixed} maxDepth (optional) The max depth to search as a number or element (defaults to 50 || document.body)
         * @param {Boolean} returnEl (optional) True to return a Ext.Element object instead of DOM node
         * @return {HTMLElement} The matching DOM node (or null if no match was found)
         */
        findParent : function(simpleSelector, maxDepth, returnEl){
            var p = this.dom,
                D = this.getDocument(),
                b = D.body,
                depth = 0,
                stopEl;
            if(Ext.isGecko && OPString.call(p) == '[object XULElement]') {
                return null;
            }
            maxDepth = maxDepth || 50;
            if (isNaN(maxDepth)) {
                stopEl = Ext.getDom(maxDepth, null, D);
                maxDepth = Number.MAX_VALUE;
            }
            while(p && p.nodeType == 1 && depth < maxDepth && p != b && p != stopEl){
                if(Ext.DomQuery.is(p, simpleSelector)){
                    return returnEl ? Ext.get(p, D) : p;
                }
                depth++;
                p = p.parentNode;
            }
            return null;
        },
        /**
         *  Store the current overflow setting and clip overflow on the element - use <tt>{@link #unclip}</tt> to remove
         * @return {Ext.Element} this
         */
        clip : function(){
            var me = this,
                dom = me.dom;
                
            if(!data(dom, ISCLIPPED)){
                data(dom, ISCLIPPED, true);
                data(dom, ORIGINALCLIP, {
                    o: me.getStyle(OVERFLOW),
                    x: me.getStyle(OVERFLOWX),
                    y: me.getStyle(OVERFLOWY)
                });
                me.setStyle(OVERFLOW, HIDDEN);
                me.setStyle(OVERFLOWX, HIDDEN);
                me.setStyle(OVERFLOWY, HIDDEN);
            }
            return me;
        },
    
        /**
         *  Return clipping (overflow) to original clipping before <tt>{@link #clip}</tt> was called
         * @return {Ext.Element} this
         */
        unclip : function(){
            var me = this,
                dom = me.dom;
                
            if(data(dom, ISCLIPPED)){
                data(dom, ISCLIPPED, false);
                var o = data(dom, ORIGINALCLIP);
                if(o.o){
                    me.setStyle(OVERFLOW, o.o);
                }
                if(o.x){
                    me.setStyle(OVERFLOWX, o.x);
                }
                if(o.y){
                    me.setStyle(OVERFLOWY, o.y);
                }
            }
            return me;
        },
        
        getViewSize : function(){
            var doc = this.getDocument(),
                d = this.dom,
                isDoc = (d == doc || d == doc.body);

            // If the body, use Ext.lib.Dom
            if (isDoc) {
                var extdom = Ext.lib.Dom;
                return {
                    width : extdom.getViewWidth(),
                    height : extdom.getViewHeight()
                }

            // Else use clientHeight/clientWidth
            } else {
                return {
                    width : d.clientWidth,
                    height : d.clientHeight
                }
            }
        },
        /**
        * <p>Returns the dimensions of the element available to lay content out in.<p>
        *
        * getStyleSize utilizes prefers style sizing if present, otherwise it chooses the larger of offsetHeight/clientHeight and offsetWidth/clientWidth.
        * To obtain the size excluding scrollbars, use getViewSize
        *
        * Sizing of the document body is handled at the adapter level which handles special cases for IE and strict modes, etc.
        */

        getStyleSize : function(){
            var me = this,
                w, h,
                doc = this.getDocument(),
                d = this.dom,
                isDoc = (d == doc || d == doc.body),
                s = d.style;

            // If the body, use Ext.lib.Dom
            if (isDoc) {
                var extdom = Ext.lib.Dom;
                return {
                    width : extdom.getViewWidth(),
                    height : extdom.getViewHeight()
                }
            }
            // Use Styles if they are set
            if(s.width && s.width != 'auto'){
                w = parseFloat(s.width);
                if(me.isBorderBox()){
                   w -= me.getFrameWidth('lr');
                }
            }
            // Use Styles if they are set
            if(s.height && s.height != 'auto'){
                h = parseFloat(s.height);
                if(me.isBorderBox()){
                   h -= me.getFrameWidth('tb');
                }
            }
            // Use getWidth/getHeight if style not set.
            return {width: w || me.getWidth(true), height: h || me.getHeight(true)};
        }
    });
   
    Ext.apply(ELD , {
        /**
         * Resolve the current document context of the passed Element
         */
        getDocument : function(el, accessTest){
          var dom= null;
          try{
            dom = Ext.getDom(el, null, null); //will fail if El.dom is non "same-origin" document
          }catch(ex){}

          var isDoc = Ext.isDocument(dom);
          if(isDoc){
            if(accessTest){
                return Ext.isDocument(dom, accessTest) ? dom : null;
            }
            return dom;
          }
          return dom ?
                dom.ownerDocument ||  //Element
                dom.document //Window
                : null;
        },

        /**
         * Return the Compatability Mode of the passed document or Element
         */
        docIsStrict : function(doc){
            return (Ext.isDocument(doc) ? doc : this.getDocument(doc)).compatMode == "CSS1Compat";
        },

        getViewWidth : Ext.overload ([
           ELD.getViewWidth || function(full){},
            function() { return this.getViewWidth(false);},
            function(full, doc) {
                return full ? this.getDocumentWidth(doc) : this.getViewportWidth(doc);
            }]
         ),

        getViewHeight : Ext.overload ([
            ELD.getViewHeight || function(full){},
            function() { return this.getViewHeight(false);},
            function(full, doc) {
                return full ? this.getDocumentHeight(doc) : this.getViewportHeight(doc);
            }]),

        getDocumentHeight: Ext.overload([
           ELD.getDocumentHeight || emptyFn,
           function(doc) {
            if(doc=this.getDocument(doc)){
              return Math.max(
                 !this.docIsStrict(doc) ? doc.body.scrollHeight : doc.documentElement.scrollHeight
                 , this.getViewportHeight(doc)
                 );
            }
            return undefined;
           }
         ]),

        getDocumentWidth: Ext.overload([
           ELD.getDocumentWidth || emptyFn,
           function(doc) {
              if(doc=this.getDocument(doc)){
                return Math.max(
                 !this.docIsStrict(doc) ? doc.body.scrollWidth : doc.documentElement.scrollWidth
                 , this.getViewportWidth(doc)
                 );
              }
              return undefined;
            }
        ]),

        getViewportHeight: Ext.overload([
           ELD.getViewportHeight || emptyFn,
           function(doc){
             if(doc=this.getDocument(doc)){
                if(Ext.isIE){
                    return this.docIsStrict(doc) ? doc.documentElement.clientHeight : doc.body.clientHeight;
                }else{
                    return doc.defaultView.innerHeight;
                }
             }
             return undefined;
           }
        ]),

        getViewportWidth: Ext.overload([
           ELD.getViewportWidth || emptyFn,
           function(doc) {
              if(doc=this.getDocument(doc)){
                return !this.docIsStrict(doc) && !Ext.isOpera ? doc.body.clientWidth :
                   Ext.isIE ? doc.documentElement.clientWidth : doc.defaultView.innerWidth;
              }
              return undefined;
            }
        ]),

        getXY : Ext.overload([
            ELD.getXY || emptyFn,
            function(el, doc) {
                if(typeof el=='string'){
	                el = Ext.getDom(el, null, doc);
	                var D= this.getDocument(el),
	                    bd = D ? (D.body || D.documentElement): null;
	
	                if(!el || !bd || el == bd){ return [0, 0]; }
                }
                return this.getXY(el);
            }
          ])
    });

    var GETDOC = ELD.getDocument,
        flies = El._flyweights;

    /**
     * @private
     * Add Ext.fly support for targeted document contexts
     */
    
    Ext.fly = El.fly = function(el, named, doc){
        var ret = null;
        named = named || '_global';

        if (el = Ext.getDom(el, null, doc)) {
            (ret = flies[named] = (flies[named] || new El.Flyweight())).dom = el;
            Ext.isDocument(el) && (ret._isDoc = true);
        }
        return ret;
    };

    var flyFn = function(){};
    flyFn.prototype = El.prototype;

    // dom is optional
    El.Flyweight = function(dom){
       this.dom = dom;
    };

    El.Flyweight.prototype = new flyFn();
    El.Flyweight.prototype.isFlyweight = true;
    
    function addListener(el, ename, fn, task, wrap, scope){
        el = Ext.getDom(el);
        if(!el){ return; }

        var id = Ext.id(el),
            cache = resolveCache(el);
            cache[id] || El.addToCache(el, id, cache);
            
         var es = cache[id].events || {}, wfn;

        wfn = E.on(el, ename, wrap);
        es[ename] = es[ename] || [];
        es[ename].push([fn, wrap, scope, wfn, task]);

        // this is a workaround for jQuery and should somehow be removed from Ext Core in the future
        // without breaking ExtJS.
        if(el.addEventListener && ename == "mousewheel" ){ 
            var args = ["DOMMouseScroll", wrap, false];
            el.addEventListener.apply(el, args);
            Ext.EventManager.addListener(window, 'beforeunload', function(){
                el.removeEventListener.apply(el, args);
            });
        }
        if(ename == "mousedown" && DOC == el){ // fix stopped mousedowns on the document
            Ext.EventManager.stoppedMouseDownEvent.addListener(wrap);
        }
    };

    function createTargeted(h, o){
        return function(){
            var args = Ext.toArray(arguments);
            if(o.target == Ext.EventObject.setEvent(args[0]).target){
                h.apply(this, args);
            }
        };
    };

    function createBuffered(h, o, task){
        return function(e){
            // create new event object impl so new events don't wipe out properties
            task.delay(o.buffer, h, null, [new Ext.EventObjectImpl(e)]);
        };
    };

    function createSingle(h, el, ename, fn, scope){
        return function(e){
            Ext.EventManager.removeListener(el, ename, fn, scope);
            h(e);
        };
    };

    function createDelayed(h, o, fn){
        return function(e){
            var task = new Ext.util.DelayedTask(h);
            (fn.tasks || (fn.tasks = [])).push(task);
            task.delay(o.delay || 10, h, null, [new Ext.EventObjectImpl(e)]);
        };
    };

    function listen(element, ename, opt, fn, scope){
        var o = !Ext.isObject(opt) ? {} : opt,
            el = Ext.getDom(element), task;

        fn = fn || o.fn;
        scope = scope || o.scope;

        if(!el){
            throw "Error listening for \"" + ename + '\". Element "' + element + '" doesn\'t exist.';
        }
        function h(e){
            // prevent errors while unload occurring
            if(!window.Ext){ return; }
            e = Ext.EventObject.setEvent(e);
            var t;
            if (o.delegate) {
                if(!(t = e.getTarget(o.delegate, el))){
                    return;
                }
            } else {
                t = e.target;
            }
            if (o.stopEvent) {
                e.stopEvent();
            }
            if (o.preventDefault) {
               e.preventDefault();
            }
            if (o.stopPropagation) {
                e.stopPropagation();
            }
            if (o.normalized) {
                e = e.browserEvent;
            }

            fn.call(scope || el, e, t, o);
        };
        if(o.target){
            h = createTargeted(h, o);
        }
        if(o.delay){
            h = createDelayed(h, o, fn);
        }
        if(o.single){
            h = createSingle(h, el, ename, fn, scope);
        }
        if(o.buffer){
            task = new Ext.util.DelayedTask(h);
            h = createBuffered(h, o, task);
        }

        addListener(el, ename, fn, task, h, scope);
        return h;
    };

    Ext.apply(Evm ,{
         addListener : Evm.on = function(element, eventName, fn, scope, options){
            if(typeof eventName == 'object'){
                var o = eventName, e, val;
                for(e in o){
                    if(!o.hasOwnProperty(e)) {
                        continue;
                    }
                    val = o[e];
                    if(!propRe.test(e)){
                        if(Ext.isFunction(val)){
                            // shared options
                            listen(element, e, o, val, o.scope);
                        }else{
                            // individual options
                            listen(element, e, val);
                        }
                    }
                }
            } else {
                listen(element, eventName, options, fn, scope);
            }
        },

        /**
         * Removes an event handler from an element.  The shorthand version {@link #un} is equivalent.  Typically
         * you will use {@link Ext.Element#removeListener} directly on an Element in favor of calling this version.
         * @param {String/HTMLElement} el The id or html element from which to remove the listener.
         * @param {String} eventName The name of the event.
         * @param {Function} fn The handler function to remove. <b>This must be a reference to the function passed into the {@link #addListener} call.</b>
         * @param {Object} scope If a scope (<b><code>this</code></b> reference) was specified when the listener was added,
         * then this must refer to the same object.
         */
        removeListener : Evm.un = function(element, eventName, fn, scope){
            var el = Ext.getDom(element);
            el && Ext.get(el);
            var elCache = el ? resolveCache(el) : {},
                f = el && ((elCache[el.id]||{events:{}}).events)[eventName] || [],
                wrap, i, l, k, len, fnc, evs;

            for (i = 0, len = f.length; i < len; i++) {
                /* 0 = Original Function,
                   1 = Event Manager Wrapped Function,
                   2 = Scope,
                   3 = Adapter Wrapped Function,
                   4 = Buffered Task
                */
                if (Ext.isArray(fnc = f[i]) && fnc[0] == fn && (!scope || fnc[2] == scope)) {
                    fnc[4] && fnc[4].cancel();
                    k = fn.tasks && fn.tasks.length;
                    if(k) {
                        while(k--) {
                            fn.tasks[k].cancel();
                        }
                        delete fn.tasks;
                    }
                    wrap = fnc[1];
                    E.un(el, eventName, E.extAdapter ? fnc[3] : wrap);
                    
                    // jQuery workaround that should be removed from Ext Core
                    if(wrap && eventName == "mousewheel" && el.addEventListener ){
                        el.removeEventListener("DOMMouseScroll", wrap, false);
                    }
        
                    if(wrap && eventName == "mousedown" && DOC == el){ // fix stopped mousedowns on the document
                        Ext.EventManager.stoppedMouseDownEvent.removeListener(wrap);
                    }
                    
                    f.splice(i,1);
                    if (f.length === 0) {
                        delete elCache[el.id].events[eventName];
                    }
                    evs = elCache[el.id].events;
                    for (k in evs) {
                        if(evs.hasOwnProperty(k)) {
	                         return false;
	                    }
                    }
                    elCache[el.id].events = {};
                    return false;
                }
            }

            
        },

        /**
         * Removes all event handers from an element.  Typically you will use {@link Ext.Element#removeAllListeners}
         * directly on an Element in favor of calling this version.
         * @param {String/HTMLElement} el The id or html element from which to remove all event handlers.
         */
        removeAll : function(el){
            if (!(el = Ext.getDom(el))) {
                return;
            }
            var id = el.id,
                elCache = resolveCache(el)||{},
                es = elCache[id] || {},
                ev = es.events || {},
                f, i, len, ename, fn, k, wrap;

            for(ename in ev){
                if(ev.hasOwnProperty(ename)){
                    f = ev[ename];
                    /* 0 = Original Function,
                       1 = Event Manager Wrapped Function,
                       2 = Scope,
                       3 = Adapter Wrapped Function,
                       4 = Buffered Task
                    */
                    for (i = 0, len = f.length; i < len; i++) {
                        fn = f[i];
                        fn[4] && fn[4].cancel();
                        if(fn[0] && fn[0].tasks && (k = fn[0].tasks.length)) {
                            while(k--) {
                                fn[0].tasks[k].cancel();
                            }
                            delete fn.tasks;
                        }
                        
                        wrap =  fn[1];
                        E.un(el, ename, E.extAdapter ? fn[3] : wrap);

                        // jQuery workaround that should be removed from Ext Core
                        if(wrap && el.addEventListener && ename == "mousewheel"){
                            el.removeEventListener("DOMMouseScroll", wrap, false);
                        }

                        // fix stopped mousedowns on the document
                        if(wrap && (DOC == el) && ename == "mousedown"){
                            Ext.EventManager.stoppedMouseDownEvent.removeListener(wrap);
                        }
                    }
                }
            }
            elCache[id] && (elCache[id].events = {});
        },

        getListeners : function(el, eventName) {
            el = Ext.getDom(el);
            if (!el) {
                return;
            }
            var id = (Ext.get(el)||{}).id,
                elCache = resolveCache(el),
                es = ( elCache[id] || {} ).events || {};

            return es[eventName] || null;
        },

        purgeElement : function(el, recurse, eventName) {
            el = Ext.getDom(el);
            var id = Ext.id(el),
                elCache = resolveCache(el),
                es = (elCache[id] || {}).events || {},
                i, f, len;
            if (eventName) {
                if (es.hasOwnProperty(eventName)) {
                    f = es[eventName];
                    for (i = 0, len = f.length; i < len; i++) {
                        Evm.removeListener(el, eventName, f[i][0]);
                    }
                }
            } else {
                Evm.removeAll(el);
            }
            if (recurse && el && el.childNodes) {
                for (i = 0, len = el.childNodes.length; i < len; i++) {
                    Evm.purgeElement(el.childNodes[i], recurse, eventName);
                }
            }
        }
    });
    
    // deprecated, call from EventManager
    E.getListeners = function(el, eventName) {
       return Ext.EventManager.getListeners(el, eventName);
    };

    /** @sourceURL=<multidom.js> */
    Ext.provide && Ext.provide('multidom');
 })();/* global Ext */
/*
 * Copyright 2007-2010, Active Group, Inc.  All rights reserved.
 * ******************************************************************************
 * This file is distributed on an AS IS BASIS WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * ***********************************************************************************
 * @version 2.1.4
 * [For Ext 3.1.1 or higher only]
 *
 * License: ux.ManagedIFrame, ux.ManagedIFrame.Panel, ux.ManagedIFrame.Portlet, ux.ManagedIFrame.Window  
 * are licensed under the terms of the Open Source GPL 3.0 license:
 * http://www.gnu.org/licenses/gpl.html
 *
 * Commercial use is prohibited without a Commercial Developement License. See
 * http://licensing.theactivegroup.com.
 *
 * Donations are welcomed: http://donate.theactivegroup.com
 *
 */
 
(function(){
    
    var El = Ext.Element, 
        ElFrame, 
        ELD = Ext.lib.Dom,
        EMPTYFN = function(){},
        OP = Object.prototype,
        addListener = function () {
            var handler;
            if (window.addEventListener) {
                handler = function F(el, eventName, fn, capture) {
                    el.addEventListener(eventName, fn, !!capture);
                };
            } else if (window.attachEvent) {
                handler = function F(el, eventName, fn, capture) {
                    el.attachEvent("on" + eventName, fn);
                };
            } else {
                handler = function F(){};
            }
            var F = null; //Gbg collect
            return handler;
        }(),
       removeListener = function() {
            var handler;
            if (window.removeEventListener) {
                handler = function F(el, eventName, fn, capture) {
                    el.removeEventListener(eventName, fn, (capture));
                };
            } else if (window.detachEvent) {
                handler = function F(el, eventName, fn) {
                    el.detachEvent("on" + eventName, fn);
                };
            } else {
                handler = function F(){};
            }
            var F = null; //Gbg collect
            return handler;
        }();
 
  //assert multidom support: REQUIRED for Ext 3 or higher!
  if(typeof ELD.getDocument != 'function'){
     alert("MIF 2.1.4 requires multidom support" );
  }
  //assert Ext 3.1.1+ 
  if(!Ext.elCache || parseInt( Ext.version.replace(/\./g,''),10) < 311 ) {
    alert ('Ext Release '+Ext.version+' is not supported');
   }
  
  Ext.ns('Ext.ux.ManagedIFrame', 'Ext.ux.plugin');
  
  var MIM, MIF = Ext.ux.ManagedIFrame, MIFC;
  var frameEvents = ['documentloaded',
                     'domready',
                     'focus',
                     'blur',
                     'resize',
                     'scroll',
                     'unload',
                     'scroll',
                     'exception', 
                     'message',
                     'reset'];
                     
    var reSynthEvents = new RegExp('^('+frameEvents.join('|')+ ')', 'i');

    /**
     * @class Ext.ux.ManagedIFrame.Element
     * @extends Ext.Element
     * @version 2.1.4 
     * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a> 
     * @author Doug Hendricks. Forum ID: <a href="http://extjs.com/forum/member.php?u=8730">hendricd</a> 
     * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
     * @copyright 2007-2010, Active Group, Inc. All rights reserved.
     * @constructor Create a new Ext.ux.ManagedIFrame.Element directly. 
     * @param {String/HTMLElement} element
     * @param {Boolean} forceNew (optional) By default the constructor checks to see if there is already an instance of this element in the cache and if there is it returns the same instance. This will skip that check (useful for extending this class).
     * @param {DocumentElement} (optional) Document context uses to resolve an Element search by its id.
     */
     
    Ext.ux.ManagedIFrame.Element = Ext.extend(Ext.Element, {
                         
            constructor : function(element, forceNew, doc ){
                var d = doc || document,
                	elCache  = ELD.resolveDocumentCache(d),
                    dom = Ext.getDom(element, false, d);
                
                if(!dom || !(/^(iframe|frame)/i).test(dom.tagName)) { // invalid id/element
                    return null;
                }
                var id = Ext.id(dom);
                
                /**
                 * The DOM element
                 * @type HTMLElement
                 */
                this.dom = dom;
                
                /**
                 * The DOM element ID
                 * @type String
                 */
                this.id = id ;
                
                (elCache[id] || 
                   (elCache[id] = {
                     el: this,
                     events : {},
                     data : {}
                    })
                ).el = this;
                
                this.dom.name || (this.dom.name = this.id);
                 
                if(Ext.isIE){
                     document.frames && (document.frames[this.dom.name] || (document.frames[this.dom.name] = this.dom));
                 }
                 
                this.dom.ownerCt = this;
                MIM.register(this);

                if(!this._observable){
	                    (this._observable = new Ext.util.Observable()).addEvents(
	                    
	                    /**
	                     * Fires when the iFrame has reached a loaded/complete state.
	                     * @event documentloaded
	                     * @param {Ext.ux.MIF.Element} this
	                     */
	                    'documentloaded',
	                    
	                    /**
	                     * Fires ONLY when an iFrame's Document(DOM) has reach a
	                     * state where the DOM may be manipulated ('same origin' policy)
	                     * Note: This event is only available when overwriting the iframe
	                     * document using the update or load methods and "same-origin"
	                     * documents. Returning false from the eventHandler stops further event
	                     * (documentloaded) processing.
	                     * @event domready 
	                     * @param {Ext.ux.MIF.Element} this
	                     */
	
	                    'domready',
	                    
	                    /**
	                     * Fires when the frame actions raise an error
	                     * @event exception
	                     * @param {Ext.ux.MIF.Element} this.iframe
	                     * @param {Error/string} exception
	                     */
	                     'exception',
	                     
	                    /**
	                     * Fires when the frame's window is resized.  This event, when raised from a "same-origin" frame,
	                     * will send current height/width reports with the event.
	                     * @event resize
	                     * @param {Ext.ux.MIF.Element} this.iframe
	                     * @param {Object} documentSize A height/width object signifying the new document size
	                     * @param {Object} viewPortSize A height/width object signifying the size of the frame's viewport
	                     * @param {Object} viewSize A height/width object signifying the size of the frame's view
	                     */
	                     'resize',
	                     
	                    /**
	                     * Fires upon receipt of a message generated by window.sendMessage
	                     * method of the embedded Iframe.window object
	                     * @event message
	                     * @param {Ext.ux.MIF} this.iframe
	                     * @param {object}
	                     *            message (members: type: {string} literal "message", data
	                     *            {Mixed} [the message payload], domain [the document domain
	                     *            from which the message originated ], uri {string} the
	                     *            document URI of the message sender source (Object) the
	                     *            window context of the message sender tag {string} optional
	                     *            reference tag sent by the message sender
	                     * <p>Alternate event handler syntax for message:tag filtering Fires upon
	                     * receipt of a message generated by window.sendMessage method which
	                     * includes a specific tag value of the embedded Iframe.window object
	                     */
	                    'message',
	
	                    /**
	                     * Fires when the frame is blurred (loses focus).
	                     * @event blur
	                     * @param {Ext.ux.MIF} this
	                     * @param {Ext.Event}
	                     *            Note: This event is only available when overwriting the
	                     *            iframe document using the update method and to pages
	                     *            retrieved from a "same domain". Returning false from the
	                     *            eventHandler [MAY] NOT cancel the event, as this event is
	                     *            NOT ALWAYS cancellable in all browsers.
	                     */
	                     'blur',
	
	                    /**
	                     * Fires when the frame gets focus. Note: This event is only available
	                     * when overwriting the iframe document using the update method and to
	                     * pages retrieved from a "same domain". Returning false from the
	                     * eventHandler [MAY] NOT cancel the event, as this event is NOT ALWAYS
	                     * cancellable in all browsers.
	                     * @event focus
	                     * @param {Ext.ux.MIF.Element} this
	                     * @param {Ext.Event}
	                     *
	                    */
	                    'focus',
	
	                    /**
	                     * Note: This event is only available when overwriting the iframe
	                     * document using the update method and to pages retrieved from a "same-origin"
	                     * domain. Note: Opera does not raise this event.
	                     * @event unload * Fires when(if) the frames window object raises the unload event
	                     * @param {Ext.ux.MIF.Element} this.
	                     * @param {Ext.Event}
	                     */
	                     'unload',
	                     
	                     /**
	                     * Note: This event is only available when overwriting the iframe
	                     * document using the update method and to pages retrieved from a "same-origin"
	                     * domain.  To prevent numerous scroll events from being raised use the buffer listener 
	                     * option to limit the number of times the event is raised.
	                     * @event scroll 
	                     * @param {Ext.ux.MIF.Element} this.
	                     * @param {Ext.Event}
	                     */
	                     'scroll',
	                     
	                    /**
	                     * Fires when the iFrame has been reset to a neutral domain state (blank document).
	                     * @event reset
	                     * @param {Ext.ux.MIF.Element} this
	                     */
	                    'reset'
	                 );
	                    //  Private internal document state events.
	                 this._observable.addEvents('_docready','_docload');
                 } 
                 
                 // Hook the Iframes loaded and error state handlers
                 this.on(
                    Ext.isIE? 'readystatechange' : 'load', 
                    this.loadHandler, 
                    this, 
                    /**
                     * Opera still fires LOAD events for images within the FRAME as well,
                     * so we'll buffer hopefully catching one of the later events
                     */ 
                    Ext.isOpera ? {buffer: this.operaLoadBuffer|| 2000} : null
                 );
                 this.on('error', this.loadHandler, this);
            },

            /** @private
             * Removes the MIFElement interface from the FRAME Element.
             * It does NOT remove the managed FRAME from the DOM.  Use the {@link Ext.#ux.ManagedIFrame.Element-remove} method to perfom both functions.
             */
            destructor   :  function () {

                MIM.deRegister(this);
                this.removeAllListeners();
                Ext.destroy(this.frameShim, this.DDM);
                this.hideMask(true);
                delete this.loadMask;
                this.reset(); 
                this.manager = null;
                this.dom.ownerCt = null;
            },
            
            /**
             * Deep cleansing childNode Removal
             * @param {Boolean} forceReclean (optional) By default the element
             * keeps track if it has been cleansed already so
             * you can call this over and over. However, if you update the element and
             * need to force a reclean, you can pass true.
             * @param {Boolean} deep (optional) Perform a deep cleanse of all childNodes as well.
             */
            cleanse : function(forceReclean, deep){
                if(this.isCleansed && forceReclean !== true){
                    return this;
                }
                var d = this.dom, n = d.firstChild, nx;
                while(d && n){
                     nx = n.nextSibling;
                     deep && Ext.fly(n).cleanse(forceReclean, deep);
                     Ext.removeNode(n);
                     n = nx;
                }
                this.isCleansed = true;
                return this;
            },

            /** (read-only) The last known URI set programmatically by the Component
             * @property  
             * @type {String|Function}
             */
            src     : null,

            /** (read-only) For "same-origin" frames only.  Provides a reference to
             * the Ext.util.CSS singleton to manipulate the style sheets of the frame's
             * embedded document.
             *
             * @property
             * @type Ext.util.CSS
             */
            CSS     : null,

            /** Provides a reference to the managing Ext.ux.MIF.Manager instance.
             *
             * @property
             * @type Ext.ux.MIF.Manager
             */
            manager : null,
            
            /**
             * @cfg {Number} operaLoadBuffer Listener buffer time (in milliseconds) to buffer
             * Opera's errant load events (fired for inline images as well) for IFRAMES.
             */
            operaLoadBuffer   : 2000,

            /**
              * @cfg {Boolean} disableMessaging False to enable cross-frame messaging API
              * @default true
              *
              */
            disableMessaging  :  true,

             /**
              * @cfg {Integer} domReadyRetries 
              * Maximum number of domready event detection retries for IE.  IE does not provide
              * a native DOM event to signal when the frames DOM may be manipulated, so a polling process
              * is used to determine when the documents BODY is available. <p> Certain documents may not contain
              * a BODY tag:  eg. MHT(rfc/822), XML, or other non-HTML content. Detection polling will stop after this number of 2ms retries 
              * or when the documentloaded event is raised.</p>
              * @default 7500 (* 2 = 15 seconds) 
              */
            domReadyRetries   :  7500,
            
            /**
             * True to set focus on the frame Window as soon as its document
             * reports loaded.  <p>(Many external sites use IE's document.createRange to create 
             * DOM elements, but to be successful, IE requires that the FRAME have focus before
             * such methods are called)</p>
             * @cfg focusOnLoad
             * @default true if IE
             */
            focusOnLoad   : Ext.isIE,
            
            /**
              * Toggles raising of events for URL actions that the Component did not initiate. 
              * @cfg {Boolean} eventsFollowFrameLinks set true to propogate domready and documentloaded
              * events anytime the IFRAME's URL changes
              * @default true
              */
            eventsFollowFrameLinks   : true,
           

            /**
             * Removes the FRAME from the DOM and deletes it from the cache
             */
            remove  : function(){
                this.destructor.apply(this, arguments);
                ElFrame.superclass.remove.apply(this,arguments);
            },
            
            /**
             * Return the ownerDocument property of the IFRAME Element.
             * (Note: This is not the document context of the FRAME's loaded document. 
             * See the getFrameDocument method for that.)
             */
            getDocument :  
                function(){ return this.dom ? this.dom.ownerDocument : document;},
            
            /**
	         * Loads the frame Element with the response from a form submit to the 
	         * specified URL with the ManagedIframe.Element as it's submit target.
	         *
	         * @param {Object} submitCfg A config object containing any of the following options:
	         * <pre><code>
	         *      myIframe.submitAsTarget({
	         *         form : formPanel.form,  //optional Ext.FormPanel, Ext form element, or HTMLFormElement
	         *         url: &quot;your-url.php&quot;,
             *         action : (see url) ,
	         *         params: {param1: &quot;foo&quot;, param2: &quot;bar&quot;}, // or URL encoded string or function that returns either
	         *         callback: yourFunction,  //optional, called with the signature (frame)
	         *         scope: yourObject, // optional scope for the callback
	         *         method: 'POST', //optional form.method 
             *         encoding : "multipart/form-data" //optional, default = HTMLForm default  
	         *      });
	         *
	         * </code></pre>
             * @return {Ext.ux.ManagedIFrame.Element} this
	         *
	         */
            submitAsTarget : function(submitCfg){
                var opt = submitCfg || {}, 
                D = this.getDocument(),
  	            form = Ext.getDom(
                       opt.form ? opt.form.form || opt.form: null, false, D) || 
                  Ext.DomHelper.append(D.body, { 
                    tag: 'form', 
                    cls : 'x-hidden x-mif-form',
                    encoding : 'multipart/form-data'
                  }),
                formFly = Ext.fly(form, '_dynaForm'),
                formState = {
                    target: form.target || '',
                    method: form.method || '',
                    encoding: form.encoding || '',
                    enctype: form.enctype || '',
                    action: form.action || '' 
                 },
                encoding = opt.encoding || form.encoding,
                method = opt.method || form.method || 'POST';
        
                formFly.set({
                   target  : this.dom.name,
                   method  : method,
                   encoding: encoding,
                   action  : opt.url || opt.action || form.action
                });
                
                if(method == 'POST' || !!opt.enctype){
                    formFly.set({enctype : opt.enctype || form.enctype || encoding});
                }
                
		        var hiddens, hd, ps;
                // add any additional dynamic params
		        if(opt.params && (ps = Ext.isFunction(opt.params) ? opt.params() : opt.params)){ 
		            hiddens = [];
                     
		            Ext.iterate(ps = typeof ps == 'string'? Ext.urlDecode(ps, false): ps, 
                        function(n, v){
		                    Ext.fly(hd = D.createElement('input')).set({
		                     type : 'hidden',
		                     name : n,
		                     value: v
                            });
		                    form.appendChild(hd);
		                    hiddens.push(hd);
		                });
		        }
		
		        opt.callback && 
                    this._observable.addListener('_docready',opt.callback, opt.scope,{single:true});
                     
                this._frameAction = true;
                this._targetURI = location.href;
		        this.showMask();
		        
		        //slight delay for masking
		        (function(){
                    
		            form.submit();
                    // remove dynamic inputs
		            hiddens && Ext.each(hiddens, Ext.removeNode, Ext);

                    //Remove if dynamically generated, restore state otherwise
		            if(formFly.hasClass('x-mif-form')){
                        formFly.remove();
                    }else{
                        formFly.set(formState);
                    }
                    delete El._flyweights['_dynaForm'];
                    formFly = null;
		            this.hideMask(true);
		        }).defer(100, this);
                
                return this;
		    },

            /**
             * @cfg {String} resetUrl Frame document reset string for use with the {@link #Ext.ux.ManagedIFrame.Element-reset} method.
             * Defaults:<p> For IE on SSL domains - the current value of Ext.SSL_SECURE_URL<p> "about:blank" for all others.
             */
            resetUrl : (function(){
                return Ext.isIE && Ext.isSecure ? Ext.SSL_SECURE_URL : 'about:blank';
            })(),

            /**
             * Sets the embedded Iframe src property. Note: invoke the function with
             * no arguments to refresh the iframe based on the current src value.
             *
             * @param {String/Function} url (Optional) A string or reference to a Function that
             *            returns a URI string when called
             * @param {Boolean} discardUrl (Optional) If not passed as <tt>false</tt>
             *            the URL of this action becomes the default SRC attribute
             *            for this iframe, and will be subsequently used in future
             *            setSrc calls (emulates autoRefresh by calling setSrc
             *            without params).
             * @param {Function} callback (Optional) A callback function invoked when the
             *            frame document has been fully loaded.
             * @param {Object} scope (Optional) scope by which the callback function is
             *            invoked.
             */
            setSrc : function(url, discardUrl, callback, scope) {
                var src = url || this.src || this.resetUrl;
                
                var O = this._observable;
                this._unHook();
                Ext.isFunction(callback) && O.addListener('_docload', callback, scope||this, {single:true});
                this.showMask();
                (discardUrl !== true) && (this.src = src);
                var s = this._targetURI = (Ext.isFunction(src) ? src() || '' : src);
                try {
                    this._frameAction = true; // signal listening now
                    this.dom.src = s;
                    this.checkDOM();
                } catch (ex) {
                    O.fireEvent.call(O, 'exception', this, ex);
                }
                return this;
            },

            /**
             * Sets the embedded Iframe location using its replace method (precluding a history update). 
             * Note: invoke the function with no arguments to refresh the iframe based on the current src value.
             *
             * @param {String/Function} url (Optional) A string or reference to a Function that
             *            returns a URI string when called
             * @param {Boolean} discardUrl (Optional) If not passed as <tt>false</tt>
             *            the URL of this action becomes the default SRC attribute
             *            for this iframe, and will be subsequently used in future
             *            setSrc calls (emulates autoRefresh by calling setSrc
             *            without params).
             * @param {Function} callback (Optional) A callback function invoked when the
             *            frame document has been fully loaded.
             * @param {Object} scope (Optional) scope by which the callback function is
             *            invoked.
             *
             */
            setLocation : function(url, discardUrl, callback, scope) {

                var src = url || this.src || this.resetUrl;
                var O = this._observable;
                this._unHook();
                Ext.isFunction(callback) && O.addListener('_docload', callback, scope||this, {single:true});
                this.showMask();
                var s = this._targetURI = (Ext.isFunction(src) ? src() || '' : src);
                if (discardUrl !== true) {
                    this.src = src;
                }
                try {
                    this._frameAction = true; // signal listening now
                    this.getWindow().location.replace(s);
                    this.checkDOM();
                } catch (ex) {
                    O.fireEvent.call(O,'exception', this, ex);
                }
                return this;
            },

            /**
             * Resets the frame to a neutral (blank document) state without
             * loadMasking.
             *
             * @param {String}
             *            src (Optional) A specific reset string (eg. 'about:blank')
             *            to use for resetting the frame.
             * @param {Function}
             *            callback (Optional) A callback function invoked when the
             *            frame reset is complete.
             * @param {Object}
             *            scope (Optional) scope by which the callback function is
             *            invoked.
             */
            reset : function(src, callback, scope) {
                
                this._unHook();
                var loadMaskOff = false,
                    s = src, 
                    win = this.getWindow(),
                    O = this._observable;
                    
                if(this.loadMask){
                    loadMaskOff = this.loadMask.disabled;
                    this.loadMask.disabled = false;
                 }
                this.hideMask(true);
                
                if(win){
                    this.isReset= true;
                    var cb = callback;
	                O.addListener('_docload',
	                  function(frame) {
	                    if(this.loadMask){
	                        this.loadMask.disabled = loadMaskOff;
	                    };
	                    Ext.isFunction(cb) &&  (cb = cb.apply(scope || this, arguments));
                        O.fireEvent("reset", this);
	                }, this, {single:true});
	            
                    Ext.isFunction(s) && ( s = src());
                    s = this._targetURI = Ext.isEmpty(s, true)? this.resetUrl: s;
                    win.location ? (win.location.href = s) : O.fireEvent('_docload', this);
                }
                
                return this;
            },

           /**
            * @private
            * Regular Expression filter pattern for script tag removal.
            * @cfg {regexp} scriptRE script removal RegeXp
            * Default: "/(?:<script.*?>)((\n|\r|.)*?)(?:<\/script>)/gi"
            */
            scriptRE : /(?:<script.*?>)((\n|\r|.)*?)(?:<\/script>)/gi,

            /**
             * Write(replacing) string content into the IFrames document structure
             * @param {String} content The new content
             * @param {Boolean} loadScripts
             * (optional) true to also render and process embedded scripts
             * @param {Function} callback (Optional) A callback function invoked when the
             * frame document has been written and fully loaded. @param {Object}
             * scope (Optional) scope by which the callback function is invoked.
             */
            update : function(content, loadScripts, callback, scope) {
                loadScripts = loadScripts || this.getUpdater().loadScripts || false;
                content = Ext.DomHelper.markup(content || '');
                content = loadScripts === true ? content : content.replace(this.scriptRE, "");
                var doc;
                if ((doc = this.getFrameDocument()) && !!content.length) {
                    this._unHook();
                    this.src = null;
                    this.showMask();
                    Ext.isFunction(callback) &&
                        this._observable.addListener('_docload', callback, scope||this, {single:true});
                    this._targetURI = location.href;
                    doc.open();
                    this._frameAction = true;
                    doc.write(content);
                    doc.close();
                    this.checkDOM();

                } else {
                    this.hideMask(true);
                    Ext.isFunction(callback) && callback.call(scope, this);
                }
                
                return this;
            },
            
            /**
             * Executes a Midas command on the current document, current selection, or the given range.
             * @param {String} command The command string to execute in the frame's document context.
             * @param {Booloean} userInterface (optional) True to enable user interface (if supported by the command)
             * @param {Mixed} value (optional)
             * @param {Boolean} validate If true, the command is validated to ensure it's invocation is permitted.
             * @return {Boolean} indication whether command execution succeeded
             */
            execCommand : function(command, userInterface, value, validate){
               var doc, assert;
               if ((doc = this.getFrameDocument()) && !!command) {
                  try{
                      Ext.isIE && this.getWindow().focus();
	                  assert = validate && Ext.isFunction(doc.queryCommandEnabled) ? 
	                    doc.queryCommandEnabled(command) : true;
                  
                      return assert && doc.execCommand(command, !!userInterface, value);
                  }catch(eex){return false;}
               }
               return false;
                
            },

            /**
             * Sets the current DesignMode attribute of the Frame's document
             * @param {Boolean/String} active True (or "on"), to enable designMode
             * 
             */
            setDesignMode : function(active){
               var doc;
               (doc = this.getFrameDocument()) && 
                 (doc.designMode = (/on|true/i).test(String(active))?'on':'off');
            },
            
            /**
            * Gets this element's Updater
            * 
            * @return {Ext.ux.ManagedIFrame.Updater} The Updater
            */
            getUpdater : function(){
               return this.updateManager || 
                    (this.updateManager = new MIF.Updater(this));
                
            },

            /**
             * Method to retrieve frame's history object.
             * @return {object} or null if permission was denied
             */
            getHistory  : function(){
                var h=null;
                try{ h=this.getWindow().history; }catch(eh){}
                return h;
            },
            
            /**
             * Method to retrieve embedded frame Element objects. Uses simple
             * caching (per frame) to consistently return the same object.
             * Automatically fixes if an object was recreated with the same id via
             * AJAX or DOM.
             *
             * @param {Mixed}
             *            el The id of the node, a DOM Node or an existing Element.
             * @return {Element} The Element object (or null if no matching element
             *         was found)
             */
            get : function(el) {
                var doc = this.getFrameDocument();
                return doc? Ext.get(el, doc) : doc=null;
            },

            /**
             * Gets the globally shared flyweight Element for the frame, with the
             * passed node as the active element. Do not store a reference to this
             * element - the dom node can be overwritten by other code.
             *
             * @param {String/HTMLElement}
             *            el The dom node or id
             * @param {String}
             *            named (optional) Allows for creation of named reusable
             *            flyweights to prevent conflicts (e.g. internally Ext uses
             *            "_internal")
             * @return {Element} The shared Element object (or null if no matching
             *         element was found)
             */
            fly : function(el, named) {
                var doc = this.getFrameDocument();
                return doc ? Ext.fly(el, named, doc) : null;
            },

            /**
             * Return the dom node for the passed string (id), dom node, or
             * Ext.Element relative to the embedded frame document context.
             *
             * @param {Mixed} el
             * @return HTMLElement
             */
            getDom : function(el) {
                var d;
                if (!el || !(d = this.getFrameDocument())) {
                    return (d=null);
                }
                return Ext.getDom(el, d);
            },
            
            /**
             * Creates a {@link Ext.CompositeElement} for child nodes based on the
             * passed CSS selector (the selector should not contain an id).
             *
             * @param {String} selector The CSS selector
             * @param {Boolean} unique (optional) True to create a unique Ext.Element for
             *            each child (defaults to false, which creates a single
             *            shared flyweight object)
             * @return {Ext.CompositeElement/Ext.CompositeElementLite} The composite element
             */
            select : function(selector, unique) {
                var d; return (d = this.getFrameDocument()) ? Ext.Element.select(selector,unique, d) : d=null;
            },

            /**
             * Selects frame document child nodes based on the passed CSS selector
             * (the selector should not contain an id).
             *
             * @param {String} selector The CSS selector
             * @return {Array} An array of the matched nodes
             */
            query : function(selector) {
                var d; return (d = this.getFrameDocument()) ? Ext.DomQuery.select(selector, d): null;
            },
            
            /**
             * Removes a DOM Element from the embedded document
             * @param {Element/String} node The node id or node Element to remove
             */
            removeNode : Ext.removeNode,
            
            /**
             * @private execScript sandbox and messaging interface
             */ 
            _renderHook : function() {
                this._windowContext = null;
                this.CSS = this.CSS ? this.CSS.destroy() : null;
                this._hooked = false;
                try {
                    if (this.writeScript('(function(){(window.hostMIF = parent.document.getElementById("'
                                    + this.id
                                    + '").ownerCt)._windowContext='
                                    + (Ext.isIE
                                            ? 'window'
                                            : '{eval:function(s){return new Function("return ("+s+")")();}}')
                                    + ';})()')) {
                        var w, p = this._frameProxy, D = this.getFrameDocument();
                        if(w = this.getWindow()){
                            p || (p = this._frameProxy = this._eventProxy.createDelegate(this));    
                            addListener(w, 'focus', p);
                            addListener(w, 'blur', p);
                            addListener(w, 'resize', p);
                            addListener(w, 'unload', p);
                            D && addListener(Ext.isIE ? w : D, 'scroll', p);
                        }
                        
                        D && (this.CSS = new Ext.ux.ManagedIFrame.CSS(D));
                       
                    }
                } catch (ex) {}
                return this.domWritable();
            },
            
             /** @private : clear all event listeners and Element cache */
            _unHook : function() {
                if (this._hooked) {
                    
                    this._windowContext && (this._windowContext.hostMIF = null);
                    this._windowContext = null;
                
                    var w, p = this._frameProxy;
                    if(p && this.domWritable() && (w = this.getWindow())){
                        removeListener(w, 'focus', p);
                        removeListener(w, 'blur', p);
                        removeListener(w, 'resize', p);
                        removeListener(w, 'unload', p);
                        removeListener(Ext.isIE ? w : this.getFrameDocument(), 'scroll', p);
                    }
                }
                
                ELD.clearDocumentCache && ELD.clearDocumentCache(this.id);
                this.CSS = this.CSS ? this.CSS.destroy() : null;
                this.domFired = this._frameAction = this.domReady = this._hooked = false;
            },
            
            /** @private */
            _windowContext : null,

            /**
             * If sufficient privilege exists, returns the frame's current document
             * as an HTMLElement.
             *
             * @return {HTMLElement} The frame document or false if access to document object was denied.
             */
            getFrameDocument : function() {
                var win = this.getWindow(), doc = null;
                try {
                    doc = (Ext.isIE && win ? win.document : null)
                            || this.dom.contentDocument
                            || window.frames[this.dom.name].document || null;
                } catch (gdEx) {
                    
                    ELD.clearDocumentCache && ELD.clearDocumentCache(this.id);
                    return false; // signifies probable access restriction
                }
                doc = (doc && Ext.isFunction(ELD.getDocument)) ? ELD.getDocument(doc,true) : doc;
                
                return doc;
            },

            /**
             * Returns the frame's current HTML document object as an
             * {@link Ext.Element}.
             * @return {Ext.Element} The document
             */
            getDoc : function() {
                var D = this.getFrameDocument();
                return Ext.get(D,D); 
            },
            
            /**
             * If sufficient privilege exists, returns the frame's current document
             * body as an HTMLElement.
             *
             * @return {HTMLElement} The frame document body or Null if access to
             *         document object was denied.
             */
            getBody : function() {
                var d;
                return (d = this.getFrameDocument()) ? this.get(d.body || d.documentElement) : null;
            },

            /**
             * Attempt to retrieve the frames current URI via frame's document object
             * @return {string} The frame document's current URI or the last know URI if permission was denied.
             */
            getDocumentURI : function() {
                var URI, d;
                try {
                    URI = this.src && (d = this.getFrameDocument()) ? d.location.href: null;
                } catch (ex) { // will fail on NON-same-origin domains
                }
                return URI || (Ext.isFunction(this.src) ? this.src() : this.src);
                // fallback to last known
            },

           /**
            * Attempt to retrieve the frames current URI via frame's Window object
            * @return {string} The frame document's current URI or the last know URI if permission was denied.
            */
            getWindowURI : function() {
                var URI, w;
                try {
                    URI = (w = this.getWindow()) ? w.location.href : null;
                } catch (ex) {
                } // will fail on NON-same-origin domains
                return URI || (Ext.isFunction(this.src) ? this.src() : this.src);
                // fallback to last known
            },

            /**
             * Returns the frame's current window object.
             *
             * @return {Window} The frame Window object.
             */
            getWindow : function() {
                var dom = this.dom, win = null;
                try {
                    win = dom.contentWindow || window.frames[dom.name] || null;
                } catch (gwEx) {}
                return win;
            },
            
            /**
             * Scrolls a frame document's child element into view within the passed container.
             * @param {String} child The id of the element to scroll into view. 
             * @param {Mixed} container (optional) The container element to scroll (defaults to the frame's document.body).  Should be a 
             * string (id), dom node, or Ext.Element.
             * @param {Boolean} hscroll (optional) False to disable horizontal scroll (defaults to true)
             * @return {Ext.ux.ManagedIFrame.Element} this 
             */ 
            scrollChildIntoView : function(child, container, hscroll){
                this.fly(child, '_scrollChildIntoView').scrollIntoView(this.getDom(container) || this.getBody().dom, hscroll);
                return this;
            },

            /**
             * Print the contents of the Iframes (if we own the document)
             * @return {Ext.ux.ManagedIFrame.Element} this 
             */
            print : function() {
                try {
                    var win;
                    if( win = this.getWindow()){
                        Ext.isIE && win.focus();
                        win.print();
                    }
                } catch (ex) {
                    throw new MIF.Error('printexception' , ex.description || ex.message || ex);
                }
                return this;
            },

            /**
             * Returns the general DOM modification capability (same-origin status) of the frame. 
             * @return {Boolean} accessible If True, the frame's inner DOM can be manipulated, queried, and
             * Event Listeners set.
             */
            domWritable : function() {
                return !!Ext.isDocument(this.getFrameDocument(),true) //test access
                    && !!this._windowContext;
            },

            /**
             * eval a javascript code block(string) within the context of the
             * Iframes' window object.
             * @param {String} block A valid ('eval'able) script source block.
             * @param {Boolean} useDOM  if true, inserts the function
             * into a dynamic script tag, false does a simple eval on the function
             * definition. (useful for debugging) <p> Note: will only work after a
             * successful iframe.(Updater) update or after same-domain document has
             * been hooked, otherwise an exception is raised.
             * @return {Mixed}  
             */
            execScript : function(block, useDOM) {
                try {
                    if (this.domWritable()) {
                        if (useDOM) {
                            this.writeScript(block);
                        } else {
                            return this._windowContext.eval(block);
                        }
                    } else {
                        throw new MIF.Error('execscript-secure-context');
                    }
                } catch (ex) {
                    this._observable.fireEvent.call(this._observable,'exception', this, ex);
                    return false;
                }
                return true;
            },

            /**
             * Write a script block into the iframe's document
             * @param {String} block A valid (executable) script source block.
             * @param {object} attributes Additional Script tag attributes to apply to the script
             * Element (for other language specs [vbscript, Javascript] etc.) <p>
             * Note: writeScript will only work after a successful iframe.(Updater)
             * update or after same-domain document has been hooked, otherwise an
             * exception is raised.
             */
            writeScript : function(block, attributes) {
                attributes = Ext.apply({}, attributes || {}, {
                            type : "text/javascript",
                            text : block
                        });
                try {
                    var head, script, doc = this.getFrameDocument();
                    if (doc && typeof doc.getElementsByTagName != 'undefined') {
                        if (!(head = doc.getElementsByTagName("head")[0])) {
                            // some browsers (Webkit, Safari) do not auto-create
                            // head elements during document.write
                            head = doc.createElement("head");
                            doc.getElementsByTagName("html")[0].appendChild(head);
                        }
                        if (head && (script = doc.createElement("script"))) {
                            for (var attrib in attributes) {
                                if (attributes.hasOwnProperty(attrib)
                                        && attrib in script) {
                                    script[attrib] = attributes[attrib];
                                }
                            }
                            return !!head.appendChild(script);
                        }
                    }
                } catch (ex) {
                    this._observable.fireEvent.call(this._observable, 'exception', this, ex);

                }finally{
                    script = head = null;
                }
                return false;
            },

            /**
             * Eval a function definition into the iframe window context.
             * @param {String/Object} fn Name of the function or function map
             * object: {name:'encodeHTML',fn:Ext.util.Format.htmlEncode}
             * @param {Boolean} useDOM  if true, inserts the fn into a dynamic script tag,
             * false does a simple eval on the function definition
             * @param {Boolean} invokeIt if true, the function specified is also executed in the
             * Window context of the frame. Function arguments are not supported.
             * @example <pre><code> var trim = function(s){ return s.replace(/^\s+|\s+$/g,''); }; 
             * iframe.loadFunction('trim');
             * iframe.loadFunction({name:'myTrim',fn:String.prototype.trim || trim});</code></pre>
             */
            loadFunction : function(fn, useDOM, invokeIt) {
                var name = fn.name || fn;
                var fnSrc = fn.fn || window[fn];
                name && fnSrc && this.execScript(name + '=' + fnSrc, useDOM); // fn.toString coercion
                invokeIt && this.execScript(name + '()'); // no args only
            },

            /**
             * @private
             * Evaluate the Iframes readyState/load event to determine its
             * 'load' state, and raise the 'domready/documentloaded' event when
             * applicable.
             */
            loadHandler : function(e, target) {
                
                var rstatus = (this.dom||{}).readyState || (e || {}).type ;
                
                if (this.eventsFollowFrameLinks || this._frameAction || this.isReset ) {
                                       
	                switch (rstatus) {
	                    case 'domready' : // MIF
                        case 'DOMFrameContentLoaded' :
	                    case 'domfail' : // MIF
	                        this._onDocReady (rstatus);
	                        break;
	                    case 'load' : // Gecko, Opera, IE
	                    case 'complete' :
                            var frame = this;
	                        this._frameAction && setTimeout( function(){frame._onDocLoaded(rstatus); }, .01);
                            this._frameAction = false;
	                        break;
	                    case 'error':
	                        this._observable.fireEvent.apply(this._observable,['exception', this].concat(arguments));
	                        break;
	                    default :
	                }
                    this.frameState = rstatus;
                }
                
            },

            /**
             * @private
             * @param {String} eventName
             */
            _onDocReady  : function(eventName ){
                var w, obv = this._observable, D;
                try {
                    if(!this.isReset && this.focusOnLoad && (w = this.getWindow())){
                        w.focus(); 
                    }
                    (D = this.getDoc()) && (D.isReady = true);
                } catch(ex){}
                
                //raise internal event regardless of state.
                obv.fireEvent("_docready", this);
               
                if ( !this.domFired && 
                     (this._hooked = this._renderHook())) {
                        // Only raise if sandBox injection succeeded (same origin)
                        this.domFired = true;
                        this.isReset || obv.fireEvent.call(obv, 'domready', this);
                }
                
                this.domReady = true;
                this.hideMask();
            },

            /**
             * @private
             * @param {String} eventName
             */
            _onDocLoaded  : function(eventName ){
                var obv = this._observable, w;
                this.domReady || this._onDocReady('domready');
                
                obv.fireEvent("_docload", this);  //invoke any callbacks
                this.isReset || obv.fireEvent("documentloaded", this);
                this.hideMask(true);
                this._frameAction = this.isReset = false;
            },

            /**
             * @private
             * Poll the Iframes document structure to determine DOM ready
             * state, and raise the 'domready' event when applicable.
             */
            checkDOM : function( win) {
                if ( Ext.isGecko ) { return; } 
                // initialise the counter
                var n = 0, frame = this, domReady = false,
                    b, l, d, 
                    max = this.domReadyRetries || 2500, //default max 5 seconds 
                    polling = false,
                    startLocation = (this.getFrameDocument() || {location : {}}).location.href;
                (function() { // DOM polling for IE and others
                    d = frame.getFrameDocument() || {location : {}};
                    // wait for location.href transition
                    polling = (d.location.href !== startLocation || d.location.href === frame._targetURI);
                    if ( frame.domReady) { return;}
                    domReady = polling && ((b = frame.getBody()) && !!(b.dom.innerHTML || '').length) || false;
                    // null href is a 'same-origin' document access violation,
                    // so we assume the DOM is built when the browser updates it
                    if (d.location.href && !domReady && (++n < max)) {
                        setTimeout(arguments.callee, 2); // try again
                        return;
                    }
                    frame.loadHandler({ type : domReady ? 'domready' : 'domfail'});
                })();
            },
            
            /**
            * @private 
            */
            filterEventOptionsRe: /^(?:scope|delay|buffer|single|stopEvent|preventDefault|stopPropagation|normalized|args|delegate)$/,

           /**
            * @private override to handle synthetic events vs DOM events
            */
            addListener : function(eventName, fn, scope, options){

                if(typeof eventName == "object"){
                    var o = eventName;
                    for(var e in o){
                        if(this.filterEventOptionsRe.test(e)){
                            continue;
                        }
                        if(typeof o[e] == "function"){
                            // shared options
                            this.addListener(e, o[e], o.scope,  o);
                        }else{
                            // individual options
                            this.addListener(e, o[e].fn, o[e].scope, o[e]);
                        }
                    }
                    return;
                }

                if(reSynthEvents.test(eventName)){
                    var O = this._observable; 
                    if(O){
                        O.events[eventName] || (O.addEvents(eventName)); 
                        O.addListener.call(O, eventName, fn, scope || this, options) ;}
                }else {
                    ElFrame.superclass.addListener.call(this, eventName,
                            fn, scope || this, options);
                }
                return this;
            },

            /**
             * @private override
             * Removes an event handler from this element.
             */
            removeListener : function(eventName, fn, scope){
                var O = this._observable;
                if(reSynthEvents.test(eventName)){
                    O && O.removeListener.call(O, eventName, fn, scope || this, options);
                }else {
                  ElFrame.superclass.removeListener.call(this, eventName, fn, scope || this);
              }
              return this;
            },

            /**
             * Removes all previous added listeners from this element
             * @private override
             */
            removeAllListeners : function(){
                Ext.EventManager.removeAll(this.dom);
                var O = this._observable;
                O && O.purgeListeners.call(this._observable);
                return this;
            },
            
            /**
             * Forcefully show the defined loadMask
             * @param {String} msg Mask text to display during the mask operation, defaults to previous defined
             * loadMask config value.
             * @param {String} msgCls The CSS class to apply to the loading message element (defaults to "x-mask-loading")
             * @param {String} maskCls The CSS class to apply to the mask element
             */
            showMask : function(msg, msgCls, maskCls) {
                var lmask = this.loadMask;
                if (lmask && !lmask.disabled ){
                    this.mask(msg || lmask.msg, msgCls || lmask.msgCls, maskCls || lmask.maskCls, lmask.maskEl);
                }
            },
            
            /**
             * Hide the defined loadMask 
             * @param {Boolean} forced True to hide the mask regardless of document ready/loaded state.
             */
            hideMask : function(forced) {
                var tlm = this.loadMask || {};
                if (forced || (tlm.hideOnReady && this.domReady)) {
                     this.unmask();
                }
            },
            
            /**
             * Puts a mask over the FRAME to disable user interaction. Requires core.css.
             * @param {String} msg (optional) A message to display in the mask
             * @param {String} msgCls (optional) A css class to apply to the msg element
             * @param {String} maskCls (optional) A css class to apply to the mask element
             * @param {String/Element} maskEl (optional) A targeted Element (parent of the IFRAME) to use the masking agent
             * @return {Element} The mask element
             */
            mask : function(msg, msgCls, maskCls, maskEl){
                this._mask && this.unmask();
                var p = Ext.get(maskEl) || this.parent('.ux-mif-mask-target') || this.parent();
                if(p.getStyle("position") == "static" && 
                    !p.select('iframe,frame,object,embed').elements.length){
                        p.addClass("x-masked-relative");
                }
                
                p.addClass("x-masked");
                
                this._mask = Ext.DomHelper.append(p, {cls: maskCls || "ux-mif-el-mask"} , true);
                this._mask.setDisplayed(true);
                this._mask._agent = p;
                
                if(typeof msg == 'string'){
                     this._maskMsg = Ext.DomHelper.append(p, {cls: msgCls || "ux-mif-el-mask-msg" , style: {visibility:'hidden'}, cn:{tag:'div', html:msg}}, true);
                     this._maskMsg
                        .setVisibilityMode(Ext.Element.VISIBILITY)
                        .center(p).setVisible(true);
                }
                if(Ext.isIE && !(Ext.isIE7 && Ext.isStrict) && this.getStyle('height') == 'auto'){ // ie will not expand full height automatically
                    this._mask.setSize(undefined, this._mask.getHeight());
                }
                return this._mask;
            },

            /**
             * Removes a previously applied mask.
             */
            unmask : function(){
                
                var a;
                if(this._mask){
                    (a = this._mask._agent) && a.removeClass(["x-masked-relative","x-masked"]);
                    if(this._maskMsg){
                        this._maskMsg.remove();
                        delete this._maskMsg;
                    }
                    this._mask.remove();
                    delete this._mask;
                }
             },

             /**
              * Creates an (frontal) transparent shim agent for the frame.  Used primarily for masking the frame during drag operations.
              * @return {Ext.Element} The new shim element.
              * @param {String} imgUrl Optional Url of image source to use during shimming (defaults to Ext.BLANK_IMAGE_URL).
              * @param {String} shimCls Optional CSS style selector for the shimming agent. (defaults to 'ux-mif-shim' ).
              * @return (HTMLElement} the shim element
              */
             createFrameShim : function(imgUrl, shimCls ){
                 this.shimCls = shimCls || this.shimCls || 'ux-mif-shim';
                 this.frameShim || (this.frameShim = this.next('.'+this.shimCls) ||  //already there ?
                  Ext.DomHelper.append(
                     this.dom.parentNode,{
                         tag : 'img',
                         src : imgUrl|| Ext.BLANK_IMAGE_URL,
                         cls : this.shimCls ,
                         galleryimg : "no"
                    }, true)) ;
                 this.frameShim && (this.frameShim.autoBoxAdjust = false); 
                 return this.frameShim;
             },
             
             /**
              * Toggles visibility of the (frontal) transparent shim agent for the frame.  Used primarily for masking the frame during drag operations.
              * @param {Boolean} show Optional True to activate the shim, false to hide the shim agent.
              */
             toggleShim : function(show){
                var shim = this.frameShim || this.createFrameShim();
                var cls = this.shimCls + '-on';
                !show && shim.removeClass(cls);
                show && !shim.hasClass(cls) && shim.addClass(cls);
             },

            /**
             * Loads this panel's iframe immediately with content returned from an XHR call.
             * @param {Object/String/Function} config A config object containing any of the following options:
             * <pre><code>
             *      frame.load({
             *         url: &quot;your-url.php&quot;,
             *         params: {param1: &quot;foo&quot;, param2: &quot;bar&quot;}, // or encoded string
             *         callback: yourFunction,
             *         scope: yourObject, // optional scope for the callback
             *         discardUrl: false,
             *         nocache: false,
             *         text: &quot;Loading...&quot;,
             *         timeout: 30,
             *         scripts: false,
             *         //optional custom renderer
             *         renderer:{render:function(el, response, updater, callback){....}}  
             *      });
             * </code></pre>
             * The only required property is url. The optional properties
             *            nocache, text and scripts are shorthand for
             *            disableCaching, indicatorText and loadScripts and are used
             *            to set their associated property on this panel Updater
             *            instance.
             * @return {Ext.ManagedIFrame.Element} this
             */
            load : function(loadCfg) {
                var um;
                if (um = this.getUpdater()) {
                    if (loadCfg && loadCfg.renderer) {
                        um.setRenderer(loadCfg.renderer);
                        delete loadCfg.renderer;
                    }
                    um.update.apply(um, arguments);
                }
                return this;
            },

             /** @private
              * Frame document event proxy
              */
             _eventProxy : function(e) {
                 if (!e) return;
                 e = Ext.EventObject.setEvent(e);
                 var be = e.browserEvent || e, er, args = [e.type, this];
                 
                 if (!be['eventPhase']
                         || (be['eventPhase'] == (be['AT_TARGET'] || 2))) {
                            
                     if(e.type == 'resize'){
	                    var doc = this.getFrameDocument();
	                    doc && (args.push(
	                        { height: ELD.getDocumentHeight(doc), width : ELD.getDocumentWidth(doc) },
	                        { height: ELD.getViewportHeight(doc), width : ELD.getViewportWidth(doc) },
	                        { height: ELD.getViewHeight(false, doc), width : ELD.getViewWidth(false, doc) }
	                      ));  
	                 }
                     
                     er =  this._observable ? 
                           this._observable.fireEvent.apply(this._observable, args.concat(
                              Array.prototype.slice.call(arguments,0))) 
                           : null;
                 
	                 // same-domain unloads should clear ElCache for use with the
	                 // next document rendering
	                 (e.type == 'unload') && this._unHook();
                     
                 }
                 return er;
            },
            
            /**
	         * dispatch a message to the embedded frame-window context (same-origin frames only)
	         * @name sendMessage
	         * @param {Mixed} message The message payload.  The payload can be any supported JS type. 
	         * @param {String} tag Optional reference tag 
	         * @param {String} origin Optional domain designation of the sender (defaults
	         * to document.domain).
	         */
	        sendMessage : function(message, tag, origin) {
	          //(implemented by mifmsg.js )
	        },
            
            /**
	         * Dispatch a cross-document message (per HTML5 specification) if the browser supports it natively.
	         * @name postMessage
	         * @param {String} message Required message payload (String only)
	         * @param {String} origin (Optional) Site designation of the sender (defaults
	         * to the current site in the form: http://site.example.com ). 
	         * <p>Notes:  on IE8, this action is synchronous.<br/>
             * Messaging support requires that the optional messaging driver source 
             * file (mifmsg.js) is also included in your project.
             * 
	         */
	        postMessage : function(message ,origin ){
	            //(implemented by mifmsg.js )
	        }

    });
   
    ElFrame = Ext.Element.IFRAME = Ext.Element.FRAME = Ext.ux.ManagedIFrame.Element;
    
      
    var fp = ElFrame.prototype;
    /**
     * @ignore
     */
    Ext.override ( ElFrame , {
          
    /**
     * Appends an event handler (shorthand for {@link #addListener}).
     * @param {String} eventName The type of event to handle
     * @param {Function} fn The handler function the event invokes
     * @param {Object} scope (optional) The scope (this element) of the handler function
     * @param {Object} options (optional) An object containing standard {@link #addListener} options
     * @member Ext.Element
     * @method on
     */
        on :  fp.addListener,
        
    /**
     * Removes an event handler from this element (shorthand for {@link #removeListener}).
     * @param {String} eventName the type of event to remove
     * @param {Function} fn the method the event invokes
     * @return {MIF.Element} this
     * @member Ext.Element
     * @method un
     */
        un : fp.removeListener,
        
        getUpdateManager : fp.getUpdater
    });

  /**
   * @class Ext.ux.ManagedIFrame.ComponentAdapter
   * @version 2.1.4 
   * @author Doug Hendricks. doug[always-At]theactivegroup.com
   * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
   * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
   * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
   * @constructor
   * @desc
   * Abstract class.  This class should not be instantiated.
   */
  
   Ext.ux.ManagedIFrame.ComponentAdapter = function(){}; 
   Ext.ux.ManagedIFrame.ComponentAdapter.prototype = {
       
        /** @property */
        version : 2.14,
        
        /**
         * @cfg {String} defaultSrc the default src property assigned to the Managed Frame when the component is rendered.
         * @default null
         */
        defaultSrc : null,
        
        /**
         * @cfg {String} unsupportedText Text to display when the IFRAMES/FRAMESETS are disabled by the browser.
         *
         */
        unsupportedText : 'Inline frames are NOT enabled\/supported by your browser.',
        
        hideMode   : !Ext.isIE && !!Ext.ux.plugin.VisibilityMode ? 'nosize' : 'display',
        
        animCollapse  : Ext.isIE ,

        animFloat  : Ext.isIE ,
        
        /**
          * @cfg {Boolean} disableMessaging False to enable cross-frame messaging API
          * @default true
          *
          */
        disableMessaging : true, 
        
        /**
          * @cfg {Boolean} eventsFollowFrameLinks set true to propagate domready and documentloaded
          * events anytime the IFRAME's URL changes
          * @default true
          */
        eventsFollowFrameLinks   : true,
        
        /**
         * @cfg {object} frameConfig Frames DOM configuration options
         * This optional configuration permits override of the IFRAME's DOM attributes
         * @example
          frameConfig : {
              name : 'framePreview',
              frameborder : 1,
              allowtransparency : true
             }
         */
        frameConfig  : null,
        
        /**
         * @cfg focusOnLoad True to set focus on the frame Window as soon as its document
         * reports loaded.  (Many external sites use IE's document.createRange to create 
         * DOM elements, but to be successfull IE requires that the FRAME have focus before
         * the method is called)
         * @default false (true for Internet Explorer)
         */
        focusOnLoad   : Ext.isIE,
        
        /**
         * @property {Object} frameEl An {@link #Ext.ux.ManagedIFrame.Element} reference to rendered frame Element.
         */
        frameEl : null, 
  
        /**
         * @cfg {Boolean} useShim
         * True to use to create a transparent shimming agent for use in masking the frame during
         * drag operations.
         * @default false
         */
        useShim   : false,

        /**
         * @cfg {Boolean} autoScroll
         * True to use overflow:'auto' on the frame element and show scroll bars automatically when necessary,
         * false to clip any overflowing content (defaults to true).
         * @default true
         */
        autoScroll: true,
        
         /**
         * @cfg {String/Object} autoLoad
         * Loads this Components frame after the Component is rendered with content returned from an
         * XHR call or optionally from a form submission.  See {@link #Ext.ux.ManagedIFrame.ComponentAdapter-load} and {@link #Ext.ux.ManagedIFrame.ComponentAdapter-submitAsTarget} methods for
         * available configuration options.
         * @default null
         */
        autoLoad: null,
        
        /** @private */
        getId : function(){
             return this.id   || (this.id = "mif-comp-" + (++Ext.Component.AUTO_ID));
        },
        
        stateEvents : ['documentloaded'],
        
        stateful    : false,
        
        /**
         * Sets the autoScroll state for the frame.
         * @param {Boolean} auto True to set overflow:auto on the frame, false for overflow:hidden
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        setAutoScroll : function(auto){
            var scroll = Ext.value(auto, this.autoScroll === true);
            this.rendered && this.getFrame() &&  
                this.frameEl.setOverflow( (this.autoScroll = scroll) ? 'auto':'hidden');
            return this;
        },
        
        getContentTarget : function(){
            return this.getFrame();
        },
        
        /**
         * Returns the Ext.ux.ManagedIFrame.Element of the frame.
         * @return {Ext.ux.ManagedIFrame.Element} this.frameEl 
         */
        getFrame : function(){
             if(this.rendered){
                if(this.frameEl){ return this.frameEl;}
                var f = this.items && this.items.first ? this.items.first() : null;
                f && (this.frameEl = f.frameEl);
                return this.frameEl;
             }
             return null;
            },
        
        /**
         * Returns the frame's current window object.
         *
         * @return {Window} The frame Window object.
         */
        getFrameWindow : function() {
            return this.getFrame() ? this.frameEl.getWindow() : null;
        },

        /**
         * If sufficient privilege exists, returns the frame's current document
         * as an HTMLElement.
         *
         * @return {HTMLElement} The frame document or false if access to
         *         document object was denied.
         */
        getFrameDocument : function() {
            return this.getFrame() ? this.frameEl.getFrameDocument() : null;
        },

        /**
         * Get the embedded iframe's document as an Ext.Element.
         *
         * @return {Ext.Element object} or null if unavailable
         */
        getFrameDoc : function() {
            return this.getFrame() ? this.frameEl.getDoc() : null;
        },

        /**
         * If sufficient privilege exists, returns the frame's current document
         * body as an HTMLElement.
         *
         * @return {Ext.Element} The frame document body or Null if access to
         *         document object was denied.
         */
        getFrameBody : function() {
            return this.getFrame() ? this.frameEl.getBody() : null;
        },
        
        /**
         * Reset the embedded frame to a neutral domain state and clear its contents
          * @param {String}src (Optional) A specific reset string (eg. 'about:blank')
         *            to use for resetting the frame.
         * @param {Function} callback (Optional) A callback function invoked when the
         *            frame reset is complete.
         * @param {Object} scope (Optional) scope by which the callback function is
         *            invoked.
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        resetFrame : function() {
            this.getFrame() && this.frameEl.reset.apply(this.frameEl, arguments);
            return this;
        },
        
        /**
         * Loads the Components frame with the response from a form submit to the 
         * specified URL with the ManagedIframe.Element as it's submit target.
         * @param {Object} submitCfg A config object containing any of the following options:
         * <pre><code>
         *      mifPanel.submitAsTarget({
         *         form : formPanel.form,  //optional Ext.FormPanel, Ext form element, or HTMLFormElement
         *         url: &quot;your-url.php&quot;,
         *         params: {param1: &quot;foo&quot;, param2: &quot;bar&quot;}, // or a URL encoded string
         *         callback: yourFunction,  //optional
         *         scope: yourObject, // optional scope for the callback
         *         method: 'POST', //optional form.action (default:'POST')
         *         encoding : "multipart/form-data" //optional, default HTMLForm default
         *      });
         *
         * </code></pre>
         *
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        submitAsTarget  : function(submitCfg){
            this.getFrame() && this.frameEl.submitAsTarget.apply(this.frameEl, arguments);
            return this;
        },
        
        /**
         * Loads this Components's frame immediately with content returned from an
         * XHR call.
         *
         * @param {Object/String/Function} loadCfg A config object containing any of the following
         *            options:
         *
         * <pre><code>
         *      mifPanel.load({
         *         url: &quot;your-url.php&quot;,
         *         params: {param1: &quot;foo&quot;, param2: &quot;bar&quot;}, // or a URL encoded string
         *         callback: yourFunction,
         *         scope: yourObject, // optional scope for the callback
         *         discardUrl: false,
         *         nocache: false,
         *         text: &quot;Loading...&quot;,
         *         timeout: 30,
         *         scripts: false,
         *         submitAsTarget : false,  //optional true, to use Form submit to load the frame (see submitAsTarget method)
         *         renderer:{render:function(el, response, updater, callback){....}}  //optional custom renderer
         *      });
         *
         * </code></pre>
         *
         * The only required property is url. The optional properties
         *            nocache, text and scripts are shorthand for
         *            disableCaching, indicatorText and loadScripts and are used
         *            to set their associated property on this panel Updater
         *            instance.
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        load : function(loadCfg) {
            if(loadCfg && this.getFrame()){
                var args = arguments;
                this.resetFrame(null, function(){ 
                    loadCfg.submitAsTarget ?
                    this.submitAsTarget.apply(this,args):
                    this.frameEl.load.apply(this.frameEl,args);
                },this);
            }
            this.autoLoad = loadCfg;
            return this;
        },

        /** @private */
        doAutoLoad : function() {
            this.autoLoad && this.load(typeof this.autoLoad == 'object' ? 
                this.autoLoad : { url : this.autoLoad });
        },

        /**
         * Get the {@link #Ext.ux.ManagedIFrame.Updater} for this panel's iframe. Enables
         * Ajax-based document replacement of this panel's iframe document.
         *
         * @return {Ext.ux.ManagedIFrame.Updater} The Updater
         */
        getUpdater : function() {
            return this.getFrame() ? this.frameEl.getUpdater() : null;
        },
        
        /**
         * Sets the embedded Iframe src property. Note: invoke the function with
         * no arguments to refresh the iframe based on the current src value.
         *
         * @param {String/Function} url (Optional) A string or reference to a Function that
         *            returns a URI string when called
         * @param {Boolean} discardUrl (Optional) If not passed as <tt>false</tt>
         *            the URL of this action becomes the default SRC attribute
         *            for this iframe, and will be subsequently used in future
         *            setSrc calls (emulates autoRefresh by calling setSrc
         *            without params).
         * @param {Function} callback (Optional) A callback function invoked when the
         *            frame document has been fully loaded.
         * @param {Object} scope (Optional) scope by which the callback function is
         *            invoked.
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        setSrc : function(url, discardUrl, callback, scope) {
            this.getFrame() && this.frameEl.setSrc.apply(this.frameEl, arguments);
            return this;
        },

        /**
         * Sets the embedded Iframe location using its replace method. Note: invoke the function with
         * no arguments to refresh the iframe based on the current src value.
         *
         * @param {String/Function} url (Optional) A string or reference to a Function that
         *            returns a URI string when called
         * @param {Boolean} discardUrl (Optional) If not passed as <tt>false</tt>
         *            the URL of this action becomes the default SRC attribute
         *            for this iframe, and will be subsequently used in future
         *            setSrc calls (emulates autoRefresh by calling setSrc
         *            without params).
         * @param {Function} callback (Optional) A callback function invoked when the
         *            frame document has been fully loaded.
         * @param {Object} scope (Optional) scope by which the callback function is
         *            invoked.
         * @return {Ext.ux.ManagedIFrame.Component} this
         */
        setLocation : function(url, discardUrl, callback, scope) {
           this.getFrame() && this.frameEl.setLocation.apply(this.frameEl, arguments);
           return this;
        },

        /**
         * @private //Make it state-aware
         */
        getState : function() {
            var URI = this.getFrame() ? this.frameEl.getDocumentURI() || null : null;
            var state = this.supr().getState.call(this);
            state = Ext.apply(state || {}, 
                {defaultSrc : Ext.isFunction(URI) ? URI() : URI,
                 autoLoad   : this.autoLoad
                });
            return state;
        },
        
        /**
         * @private
         */
        setMIFEvents : function(){
            
            this.addEvents(

                    /**
                     * Fires when the iFrame has reached a loaded/complete state.
                     * @event documentloaded
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     */
                    'documentloaded',  
                      
                    /**
                     * Fires ONLY when an iFrame's Document(DOM) has reach a
                     * state where the DOM may be manipulated (ie same domain policy)
                     * Note: This event is only available when overwriting the iframe
                     * document using the update method and to pages retrieved from a "same
                     * domain". Returning false from the eventHandler stops further event
                     * (documentloaded) processing.
                     * @event domready 
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} this.frameEl
                     */
                    'domready',
                    /**
                     * Fires when the frame actions raise an error
                     * @event exception
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.MIF.Element} frameEl
                     * @param {Error/string} exception
                     */
                    'exception',

                    /**
                     * Fires upon receipt of a message generated by window.sendMessage
                     * method of the embedded Iframe.window object
                     * @event message
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} this.frameEl
                     * @param {object}
                     *            message (members: type: {string} literal "message", data
                     *            {Mixed} [the message payload], domain [the document domain
                     *            from which the message originated ], uri {string} the
                     *            document URI of the message sender source (Object) the
                     *            window context of the message sender tag {string} optional
                     *            reference tag sent by the message sender
                     * <p>Alternate event handler syntax for message:tag filtering Fires upon
                     * receipt of a message generated by window.sendMessage method which
                     * includes a specific tag value of the embedded Iframe.window object
                     *
                     */
                    'message',

                    /**
                     * Fires when the frame is blurred (loses focus).
                     * @event blur
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     * @param {Ext.Event} e Note: This event is only available when overwriting the
                     *            iframe document using the update method and to pages
                     *            retrieved from a "same domain". Returning false from the
                     *            eventHandler [MAY] NOT cancel the event, as this event is
                     *            NOT ALWAYS cancellable in all browsers.
                     */
                    'blur',

                    /**
                     * Fires when the frame gets focus. Note: This event is only available
                     * when overwriting the iframe document using the update method and to
                     * pages retrieved from a "same domain". Returning false from the
                     * eventHandler [MAY] NOT cancel the event, as this event is NOT ALWAYS
                     * cancellable in all browsers.
                     * @event focus
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     * @param {Ext.Event} e
                     *
                    */
                    'focus',
                    
                     /**
                     * Note: This event is only available when overwriting the iframe
                     * document using the update method and to pages retrieved from a "same-origin"
                     * domain.  To prevent numerous scroll events from being raised use the <i>buffer</i> listener 
                     * option to limit the number of times the event is raised.
                     * @event scroll 
                     * @param {Ext.ux.MIF.Element} this.
                     * @param {Ext.Event}
                     */
                    'scroll',
                    
                    /**
                     * Fires when the frames window is resized. Note: This event is only available
                     * when overwriting the iframe document using the update method and to
                     * pages retrieved from a "same domain". 
                     * @event resize
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     * @param {Ext.Event} e
                     * @param {Object} documentSize A height/width object signifying the new document size
                     * @param {Object} viewPortSize A height/width object signifying the size of the frame's viewport
                     * @param {Object} viewSize A height/width object signifying the size of the frame's view
                     *
                    */
                    'resize',
                    
                    /**
                     * Fires when(if) the frames window object raises the unload event
                     * Note: This event is only available when overwriting the iframe
                     * document using the update method and to pages retrieved from a "same-origin"
                     * domain. Note: Opera does not raise this event.
                     * @event unload 
                     * @memberOf Ext.ux.ManagedIFrame.ComponentAdapter
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     * @param {Ext.Event}
                     */
                    'unload',
                    
                    /**
                     * Fires when the iFrame has been reset to a neutral domain state (blank document).
                     * @event reset
                     * @param {Ext.ux.ManagedIFrame.Element} frameEl
                     */
                    'reset'
                );
        },
        
        /**
         * dispatch a message to the embedded frame-window context (same-origin frames only)
         * @name sendMessage
         * @memberOf Ext.ux.ManagedIFrame.Element
         * @param {Mixed} message The message payload.  The payload can be any supported JS type. 
         * @param {String} tag Optional reference tag 
         * @param {String} origin Optional domain designation of the sender (defaults
         * to document.domain).
         */
        sendMessage : function(message, tag, origin) {
       
          //(implemented by mifmsg.js )
        },
        //Suspend (and queue) host container events until the child MIF.Component is rendered.
        onAdd : function(C){
             C.relayTarget && this.suspendEvents(true); 
        },
        
        initRef: function() {
      
	        if(this.ref){
	            var t = this,
	                levels = this.ref.split('/'),
	                l = levels.length,
	                i;
	            for (i = 0; i < l; i++) {
	                if(t.ownerCt){
	                    t = t.ownerCt;
	                }
	            }
	            this.refName = levels[--i];
	            t[this.refName] || (t[this.refName] = this);
	            
	            this.refOwner = t;
	        }
	    }
      
   };
   
   /*
    * end Adapter
    */
   
  /**
   * @class Ext.ux.ManagedIFrame.Component
   * @extends Ext.BoxComponent
   * @version 2.1.4 
   * @author Doug Hendricks. doug[always-At]theactivegroup.com
   * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
   * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
   * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
   * @constructor
   * @base Ext.ux.ManagedIFrame.ComponentAdapter
   * @param {Object} config The config object
   */
  Ext.ux.ManagedIFrame.Component = Ext.extend(Ext.BoxComponent , { 
            
            ctype     : "Ext.ux.ManagedIFrame.Component",
            
            /** @private */
            initComponent : function() {
               
                var C = {
	                monitorResize : this.monitorResize || (this.monitorResize = !!this.fitToParent),
	                plugins : (this.plugins ||[]).concat(
	                    this.hideMode === 'nosize' && Ext.ux.plugin.VisibilityMode ? 
		                    [new Ext.ux.plugin.VisibilityMode(
		                        {hideMode :'nosize',
		                         elements : ['bwrap']
		                        })] : [] )
                  };
                  
                MIF.Component.superclass.initComponent.call(
                  Ext.apply(this,
                    Ext.apply(this.initialConfig, C)
                    ));
                    
                this.setMIFEvents();
            },   

            /** @private */
            onRender : function(ct, position){
                
                //default child frame's name to that of MIF-parent id (if not specified on frameCfg).
                var frCfg = this.frameCfg || this.frameConfig || (this.relayTarget ? {name : this.relayTarget.id}: {}) || {};
                
                //backward compatability with MIF 1.x
                var frDOM = frCfg.autoCreate || frCfg;
                frDOM = Ext.apply({tag  : 'iframe', id: Ext.id()}, frDOM);
                
                var el = Ext.getDom(this.el);

                (el && el.tagName == 'iframe') || 
                  (this.autoEl = Ext.apply({
                                    name : frDOM.id,
                                    frameborder : 0
                                   }, frDOM ));
                 
                MIF.Component.superclass.onRender.apply(this, arguments);
               
                if(this.unsupportedText){
                    ct.child('noframes') || ct.createChild({tag: 'noframes', html : this.unsupportedText || null});  
                }   
                var frame = this.el ;
                
                var F;
                if( F = this.frameEl = (this.el ? new MIF.Element(this.el.dom, true): null)){
                    
                    Ext.apply(F,{
                        ownerCt          : this.relayTarget || this,
                        disableMessaging : Ext.value(this.disableMessaging, true),
                        focusOnLoad      : Ext.value(this.focusOnLoad, Ext.isIE),
                        eventsFollowFrameLinks : Ext.value(this.eventsFollowFrameLinks ,true)
                    });
                    F.ownerCt.frameEl = F;
                    F.addClass('ux-mif'); 
                    if (this.loadMask) {
                        //resolve possible maskEl by Element name eg. 'body', 'bwrap', 'actionEl'
                        var mEl = this.loadMask.maskEl;
                        F.loadMask = Ext.apply({
                                    disabled    : false,
                                    hideOnReady : false,
                                    msgCls      : 'ext-el-mask-msg x-mask-loading',  
                                    maskCls     : 'ext-el-mask'
                                },
                                {
                                  maskEl : F.ownerCt[String(mEl)] || F.parent('.' + String(mEl)) || F.parent('.ux-mif-mask-target') || mEl 
                                },
                                Ext.isString(this.loadMask) ? {msg:this.loadMask} : this.loadMask
                              );
                        Ext.get(F.loadMask.maskEl) && Ext.get(F.loadMask.maskEl).addClass('ux-mif-mask-target');
                    }
                    
                    F._observable && 
                        (this.relayTarget || this).relayEvents(F._observable, frameEvents.concat(this._msgTagHandlers || []));
                        
                    delete this.contentEl;
                    
                    //Template support for writable frames
                    
                 }
            },
            
            /** @private */
            afterRender  : function(container) {
                MIF.Component.superclass.afterRender.apply(this,arguments);
                
                // only resize (to Parent) if the panel is NOT in a layout.
                // parentNode should have {style:overflow:hidden;} applied.
                if (this.fitToParent && !this.ownerCt) {
                    var pos = this.getPosition(), size = (Ext.get(this.fitToParent)
                            || this.getEl().parent()).getViewSize();
                    this.setSize(size.width - pos[0], size.height - pos[1]);
                }

                this.getEl().setOverflow('hidden'); //disable competing scrollers
                this.setAutoScroll();
                var F;
               /* Enable auto-Shims if the Component participates in (nested?)
                * border layout.
                * Setup event handlers on the SplitBars and region panels to enable the frame
                * shims when needed
                */
                if(F = this.frameEl){
                    var ownerCt = this.ownerCt;
                    while (ownerCt) {
                        ownerCt.on('afterlayout', function(container, layout) {
                            Ext.each(['north', 'south', 'east', 'west'],
                                    function(region) {
                                        var reg;
                                        if ((reg = layout[region]) && 
                                             reg.split && reg.split.dd &&
                                             !reg._splitTrapped) {
                                               reg.split.dd.endDrag = reg.split.dd.endDrag.createSequence(MIM.hideShims, MIM );
                                               reg.split.on('beforeresize',MIM.showShims,MIM);
                                               reg._splitTrapped = MIM._splitTrapped = true;
                                        }
                            }, this);
                        }, this, { single : true}); // and discard
                        ownerCt = ownerCt.ownerCt; // nested layouts?
                    }
                    /*
                     * Create an img shim if the component participates in a layout or forced
                     */
                    if(!!this.ownerCt || this.useShim ){ this.frameShim = F.createFrameShim(); }
                    this.getUpdater().showLoadIndicator = this.showLoadIndicator || false;
                    
                    //Resume Parent containers' events callback
                    var resumeEvents = this.relayTarget && this.ownerCt ?                         
                       this.ownerCt.resumeEvents.createDelegate(this.ownerCt) : null;
                       
                    if (this.autoload) {
                       this.doAutoLoad();
                    } else if(this.tpl && (this.frameData || this.data)) {
                       F.update(this.tpl.apply(this.frameData || this.data), true, resumeEvents);
                       delete this.frameData;
                       delete this.data;
                       return;
                    } else if(this.frameMarkup  || this.html) {
                       F.update(this.frameMarkup  || this.html , true, resumeEvents);
                       delete this.html;
                       delete this.frameMarkup;
                       return;
                    } else {
                       if (this.defaultSrc) {
                            F.setSrc(this.defaultSrc, false);
                       } else {
                            /* If this is a no-action frame, reset it first, then resume parent events
                             * allowing access to a fully reset frame by upstream afterrender/layout events
                             */ 
                            F.reset(null, resumeEvents);
                            return;
                       }
                    }
                    resumeEvents && resumeEvents();
                }
            },
            
            /** @private */
            beforeDestroy : function() {
                var F;
                if(F = this.getFrame()){
                    F.remove();
                    this.frameEl = this.frameShim = null;
                }
                this.relayTarget && (this.relayTarget.frameEl = null);
                MIF.Component.superclass.beforeDestroy.call(this);
            }
    });

    Ext.override(MIF.Component, MIF.ComponentAdapter.prototype);
    Ext.reg('mif', MIF.Component);
   
    /*
    * end Component
    */
    
  /**
   * @private
   * this function renders a child MIF.Component to MIF.Panel and MIF.Window
   * designed to be called by the constructor of higher-level MIF.Components only.
   */
  function embed_MIF(config){
    
    config || (config={});
    config.layout = 'fit';
    config.items = {
             xtype    : 'mif',
               ref    : 'mifChild',
            useShim   : true,
                  tpl : Ext.value(config.tpl , this.tpl),
           autoScroll : Ext.value(config.autoScroll , this.autoScroll),
          defaultSrc  : Ext.value(config.defaultSrc , this.defaultSrc),
         frameMarkup  : Ext.value(config.html , this.html),
           frameData  : Ext.value(config.data , this.data),
            loadMask  : Ext.value(config.loadMask , this.loadMask),
    disableMessaging  : Ext.value(config.disableMessaging, this.disableMessaging),
 eventsFollowFrameLinks : Ext.value(config.eventsFollowFrameLinks, this.eventsFollowFrameLinks),
         focusOnLoad  : Ext.value(config.focusOnLoad, this.focusOnLoad),
          frameConfig : Ext.value(config.frameConfig || config.frameCfg , this.frameConfig),
          relayTarget : this  //direct relay of events to the parent component
        };
    delete config.html;
    delete config.data;
    this.setMIFEvents();
    return config; 
    
  };
    
  /**
   * @class Ext.ux.ManagedIFrame.Panel
   * @extends Ext.Panel
   * @version 2.1.4 
   * @author Doug Hendricks. doug[always-At]theactivegroup.com
   * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
   * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
   * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
   * @constructor
   * @base Ext.ux.ManagedIFrame.ComponentAdapter
   * @param {Object} config The config object
   */

  Ext.ux.ManagedIFrame.Panel = Ext.extend( Ext.Panel , {
        ctype       : 'Ext.ux.ManagedIFrame.Panel',
        bodyCssClass: 'ux-mif-mask-target',
        constructor : function(config){
            MIF.Panel.superclass.constructor.call(this, embed_MIF.call(this, config));
         }
  });
  
  Ext.override(MIF.Panel, MIF.ComponentAdapter.prototype);
  Ext.reg('iframepanel', MIF.Panel);
    /*
    * end Panel
    */

    /**
     * @class Ext.ux.ManagedIFrame.Portlet
     * @extends Ext.ux.ManagedIFrame.Panel
     * @version 2.1.4 
     * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
     * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a> 
     * @author Doug Hendricks. Forum ID: <a href="http://extjs.com/forum/member.php?u=8730">hendricd</a> 
     * @copyright 2007-2010, Active Group, Inc. All rights reserved.
     * @constructor Create a new Ext.ux.ManagedIFramePortlet 
     * @param {Object} config The config object
     */

    Ext.ux.ManagedIFrame.Portlet = Ext.extend(Ext.ux.ManagedIFrame.Panel, {
                ctype      : "Ext.ux.ManagedIFrame.Portlet",
                anchor     : '100%',
                frame      : true,
                collapseEl : 'bwrap',
                collapsible: true,
                draggable  : true,
                cls        : 'x-portlet'
                
            });
            
    Ext.reg('iframeportlet', MIF.Portlet);
   /*
    * end Portlet
    */
    
  /**
   * @class Ext.ux.ManagedIFrame.Window
   * @extends Ext.Window
   * @version 2.1.4 
   * @author Doug Hendricks. 
   * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
   * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
   * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
   * @constructor
   * @base Ext.ux.ManagedIFrame.ComponentAdapter
   * @param {Object} config The config object
   */
    
  Ext.ux.ManagedIFrame.Window = Ext.extend( Ext.Window , 
       {
            ctype       : "Ext.ux.ManagedIFrame.Window",
            bodyCssClass: 'ux-mif-mask-target',
            constructor : function(config){
			    MIF.Window.superclass.constructor.call(this, embed_MIF.call(this, config));
            }
    });
    Ext.override(MIF.Window, MIF.ComponentAdapter.prototype);
    Ext.reg('iframewindow', MIF.Window);
    
    /*
    * end Window
    */
    
    /**
     * @class Ext.ux.ManagedIFrame.Updater
     * @extends Ext.Updater
     * @version 2.1.4 
     * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
     * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a> 
     * @author Doug Hendricks. Forum ID: <a href="http://extjs.com/forum/member.php?u=8730">hendricd</a> 
     * @copyright 2007-2010, Active Group, Inc. All rights reserved.
     * @constructor Creates a new Ext.ux.ManagedIFrame.Updater instance.
     * @param {String/Object} el The element to bind the Updater instance to.
     */
    Ext.ux.ManagedIFrame.Updater = Ext.extend(Ext.Updater, {
    
       /**
         * Display the element's "loading" state. By default, the element is updated with {@link #indicatorText}. This
         * method may be overridden to perform a custom action while this Updater is actively updating its contents.
         */
        showLoading : function(){
            this.showLoadIndicator && this.el && this.el.mask(this.indicatorText);
            
        },
        
        /**
         * Hide the Frames masking agent.
         */
        hideLoading : function(){
            this.showLoadIndicator && this.el && this.el.unmask();
        },
        
        // private
        updateComplete : function(response){
            MIF.Updater.superclass.updateComplete.apply(this,arguments);
            this.hideLoading();
        },
    
        // private
        processFailure : function(response){
            MIF.Updater.superclass.processFailure.apply(this,arguments);
            this.hideLoading();
        }
        
    }); 
    
    
    var styleCamelRe = /(-[a-z])/gi;
    var styleCamelFn = function(m, a) {
        return a.charAt(1).toUpperCase();
    };
    
    /**
     * @class Ext.ux.ManagedIFrame.CSS
     * Stylesheet interface object
     * @version 2.1.4 
     * @author Doug Hendricks. doug[always-At]theactivegroup.com
     * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
     * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
     * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
     */
    Ext.ux.ManagedIFrame.CSS = function(hostDocument) {
        var doc;
        if (hostDocument) {
            doc = hostDocument;
            return {
                rules : null,
                /** @private */
                destroy  :  function(){  return doc = null; },

                /**
                 * Creates a stylesheet from a text blob of rules. These rules
                 * will be wrapped in a STYLE tag and appended to the HEAD of
                 * the document.
                 *
                 * @param {String}
                 *            cssText The text containing the css rules
                 * @param {String} id An (optional) id to add to the stylesheet for later removal
                 * @return {StyleSheet}
                 */
                createStyleSheet : function(cssText, id) {
                    var ss;
                    if (!doc)return;
                    var head = doc.getElementsByTagName("head")[0];
                    var rules = doc.createElement("style");
                    rules.setAttribute("type", "text/css");
                    Ext.isString(id) && rules.setAttribute("id", id);

                    if (Ext.isIE) {
                        head.appendChild(rules);
                        ss = rules.styleSheet;
                        ss.cssText = cssText;
                    } else {
                        try {
                            rules.appendChild(doc.createTextNode(cssText));
                        } catch (e) {
                            rules.cssText = cssText;
                        }
                        head.appendChild(rules);
                        ss = rules.styleSheet
                                ? rules.styleSheet
                                : (rules.sheet || doc.styleSheets[doc.styleSheets.length - 1]);
                    }
                    this.cacheStyleSheet(ss);
                    return ss;
                },

                /**
                 * Removes a style or link tag by id
                 *
                 * @param {String}
                 *            id The id of the tag
                 */
                removeStyleSheet : function(id) {

                    if (!doc || !id)return;
                    var existing = doc.getElementById(id);
                    if (existing) {
                        existing.parentNode.removeChild(existing);
                    }
                },

                /**
                 * Dynamically swaps an existing stylesheet reference for a new
                 * one
                 *
                 * @param {String}
                 *            id The id of an existing link tag to remove
                 * @param {String}
                 *            url The href of the new stylesheet to include
                 */
                swapStyleSheet : function(id, url) {
                    if (!doc)return;
                    this.removeStyleSheet(id);
                    var ss = doc.createElement("link");
                    ss.setAttribute("rel", "stylesheet");
                    ss.setAttribute("type", "text/css");
                    Ext.isString(id) && ss.setAttribute("id", id);
                    ss.setAttribute("href", url);
                    doc.getElementsByTagName("head")[0].appendChild(ss);
                },

                /**
                 * Refresh the rule cache if you have dynamically added stylesheets
                 * @return {Object} An object (hash) of rules indexed by selector
                 */
                refreshCache : function() {
                    return this.getRules(true);
                },

                // private
                cacheStyleSheet : function(ss, media) {
                    this.rules || (this.rules = {});
                    
                     try{// try catch for cross domain access issue
			          
				          Ext.each(ss.cssRules || ss.rules || [], 
				            function(rule){ 
				              this.hashRule(rule, ss, media);
				          }, this);  
				          
				          //IE @imports
				          Ext.each(ss.imports || [], 
				           function(sheet){
				              sheet && this.cacheStyleSheet(sheet,this.resolveMedia([sheet, sheet.parentStyleSheet]));
				           }
				          ,this);
			          
			        }catch(e){}
                },
                 // @private
			   hashRule  :  function(rule, sheet, mediaOverride){
			      
			      var mediaSelector = mediaOverride || this.resolveMedia(rule);
			      
			      //W3C @media
			      if( rule.cssRules || rule.rules){
			          this.cacheStyleSheet(rule, this.resolveMedia([rule, rule.parentRule ]));
			      } 
			      
			       //W3C @imports
			      if(rule.styleSheet){ 
			         this.cacheStyleSheet(rule.styleSheet, this.resolveMedia([rule, rule.ownerRule, rule.parentStyleSheet]));
			      }
			      
			      rule.selectorText && 
			        Ext.each((mediaSelector || '').split(','), 
			           function(media){
			            this.rules[((media ? media.trim() + ':' : '') + rule.selectorText).toLowerCase()] = rule;
			        }, this);
			      
			   },
			
			   /**
			    * @private
			    * @param {Object/Array} rule CSS Rule (or array of Rules/sheets) to evaluate media types.
			    * @return a comma-delimited string of media types. 
			    */
			   resolveMedia  : function(rule){
			        var media;
			        Ext.each([].concat(rule),function(r){
			            if(r && r.media && r.media.length){
			                media = r.media;
			                return false;
			            }
			        });
			        return media ? (Ext.isIE ? String(media) : media.mediaText ) : '';
			     },

                /**
                 * Gets all css rules for the document
                 *
                 * @param {Boolean}
                 *            refreshCache true to refresh the internal cache
                 * @return {Object} An object (hash) of rules indexed by
                 *         selector
                 */
                getRules : function(refreshCache) {
                    if (!this.rules || refreshCache) {
                        this.rules = {};
                        if (doc) {
                            var ds = doc.styleSheets;
                            for (var i = 0, len = ds.length; i < len; i++) {
                                try {
                                    this.cacheStyleSheet(ds[i]);
                                } catch (e) {}
                            }
                        }
                    }
                    return this.rules;
                },

               /**
			    * Gets an an individual CSS rule by selector(s)
			    * @param {String/Array} selector The CSS selector or an array of selectors to try. The first selector that is found is returned.
			    * @param {Boolean} refreshCache true to refresh the internal cache if you have recently updated any rules or added styles dynamically
			    * @param {String} mediaSelector Name of optional CSS media context (eg. print, screen)
			    * @return {CSSRule} The CSS rule or null if one is not found
			    */
                getRule : function(selector, refreshCache, mediaSelector) {
                    var rs = this.getRules(refreshCache);

			        if(Ext.type(mediaSelector) == 'string'){
			            mediaSelector = mediaSelector.trim() + ':';
			        }else{
			            mediaSelector = '';
			        }
			
			        if(!Ext.isArray(selector)){
			            return rs[(mediaSelector + selector).toLowerCase()];
			        }
			        var select;
			        for(var i = 0; i < selector.length; i++){
			            select = (mediaSelector + selector[i]).toLowerCase();
			            if(rs[select]){
			                return rs[select];
			            }
			        }
			        return null;
                },

               /**
			    * Updates a rule property
			    * @param {String/Array} selector If it's an array it tries each selector until it finds one. Stops immediately once one is found.
			    * @param {String} property The css property
			    * @param {String} value The new value for the property
			    * @param {String} mediaSelector Name(s) of optional media contexts. Multiple may be specified, delimited by commas (eg. print,screen)
			    * @return {Boolean} true If a rule was found and updated
			    */
                updateRule : function(selector, property, value, mediaSelector){
    
			         Ext.each((mediaSelector || '').split(','), function(mediaSelect){    
			            if(!Ext.isArray(selector)){
			                var rule = this.getRule(selector, false, mediaSelect);
			                if(rule){
			                    rule.style[property.replace(camelRe, camelFn)] = value;
			                    return true;
			                }
			            }else{
			                for(var i = 0; i < selector.length; i++){
			                    if(this.updateRule(selector[i], property, value, mediaSelect)){
			                        return true;
			                    }
			                }
			            }
			            return false;
			         }, this);
                }
            };
        }
    };

    /**
     * @class Ext.ux.ManagedIFrame.Manager
     * @version 2.1.4 
	 * @author Doug Hendricks. doug[always-At]theactivegroup.com
	 * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
	 * @copyright 2007-2010, Active Group, Inc.  All rights reserved.
	 * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a>
	 * @singleton
     */
    Ext.ux.ManagedIFrame.Manager = function() {
        var frames = {};
        var implementation = {
            // private DOMFrameContentLoaded handler for browsers (Gecko, Webkit, Opera) that support it.
            _DOMFrameReadyHandler : function(e) {
                try {
                    var $frame ;
                    if ($frame = e.target.ownerCt){
                        $frame.loadHandler.call($frame,e);
                    }
                } catch (rhEx) {} //nested iframes will throw when accessing target.id
            },
            /**
             * @cfg {String} shimCls
             * @default "ux-mif-shim"
             * The default CSS rule applied to MIF image shims to toggle their visibility.
             */
            shimCls : 'ux-mif-shim',

            /** @private */
            register : function(frame) {
                frame.manager = this;
                frames[frame.id] = frames[frame.name] = {ref : frame };
                return frame;
            },
            /** @private */
            deRegister : function(frame) {
                delete frames[frame.id];
                delete frames[frame.name];
                
            },
            /**
             * Toggles the built-in MIF shim off on all visible MIFs
             * @methodOf Ext.ux.MIF.Manager
             *
             */
            hideShims : function() {
                var mm = MIF.Manager;
                mm.shimsApplied && Ext.select('.' + mm.shimCls, true).removeClass(mm.shimCls+ '-on');
                mm.shimsApplied = false;
            },

            /**
             * Shim ALL MIFs (eg. when a region-layout.splitter is on the move or before start of a drag operation)
             * @methodOf Ext.ux.MIF.Manager
             */
            showShims : function() {
                var mm = MIF.Manager;
                !mm.shimsApplied && Ext.select('.' + mm.shimCls, true).addClass(mm.shimCls+ '-on');
                mm.shimsApplied = true;
            },

            /**
             * Retrieve a MIF instance by its DOM ID
             * @methodOf Ext.ux.MIF.Manager
             * @param {Ext.ux.MIF/string} id
             */
            getFrameById : function(id) {
                return typeof id == 'string' ? (frames[id] ? frames[id].ref
                        || null : null) : null;
            },

            /**
             * Retrieve a MIF instance by its DOM name
             * @methodOf Ext.ux.MIF.Manager
             * @param {Ext.ux.MIF/string} name
             */
            getFrameByName : function(name) {
                return this.getFrameById(name);
            },

            /** @private */
            // retrieve the internal frameCache object
            getFrameHash : function(frame) {
                return frames[frame.id] || frames[frame.id] || null;
            },

            /** @private */
            destroy : function() {
                if (document.addEventListener && !Ext.isOpera) {
                      window.removeEventListener("DOMFrameContentLoaded", this._DOMFrameReadyHandler , false);
                }
            }
        };
        // for Gecko and any who might support it later 
        document.addEventListener && !Ext.isOpera &&
            window.addEventListener("DOMFrameContentLoaded", implementation._DOMFrameReadyHandler , false);

        Ext.EventManager.on(window, 'beforeunload', implementation.destroy, implementation);
        return implementation;
    }();
    
    MIM = MIF.Manager;
    MIM.showDragMask = MIM.showShims;
    MIM.hideDragMask = MIM.hideShims;
    
    /**
     * Shim all MIF's during a Window drag operation.
     */
    var winDD = Ext.Window.DD;
    Ext.override(winDD, {
       startDrag : winDD.prototype.startDrag.createInterceptor(MIM.showShims),
       endDrag   : winDD.prototype.endDrag.createInterceptor(MIM.hideShims)
    });

    //Previous release compatibility
    Ext.ux.ManagedIFramePanel = MIF.Panel;
    Ext.ux.ManagedIFramePortlet = MIF.Portlet;
    Ext.ux.ManagedIframe = function(el,opt){
        
        var args = Array.prototype.slice.call(arguments, 0),
            el = Ext.get(args[0]),
            config = args[0];

        if (el && el.dom && el.dom.tagName == 'IFRAME') {
            config = args[1] || {};
        } else {
            config = args[0] || args[1] || {};

            el = config.autoCreate ? Ext.get(Ext.DomHelper.append(
                    config.autoCreate.parent || Ext.getBody(), Ext.apply({
                        tag : 'iframe',
                        frameborder : 0,
                        cls : 'x-mif',
                        src : (Ext.isIE && Ext.isSecure)? Ext.SSL_SECURE_URL: 'about:blank'
                    }, config.autoCreate)))
                    : null;

            if(el && config.unsupportedText){
                Ext.DomHelper.append(el.dom.parentNode, {tag:'noframes',html: config.unsupportedText } );
            }
        }
        
        var mif = new MIF.Element(el,true);
        if(mif){
            Ext.apply(mif, {
                disableMessaging : Ext.value(config.disableMessaging , true),
                focusOnLoad : Ext.value(config.focusOnLoad , Ext.isIE),
                eventsFollowFrameLinks : Ext.value(config.eventsFollowFrameLinks ,true),
                loadMask : !!config.loadMask ? Ext.apply({
                            msg : 'Loading..',
                            msgCls : 'x-mask-loading',
                            maskEl : null,
                            hideOnReady : false,
                            disabled : false
                        }, config.loadMask) : false,
                _windowContext : null
                
            });
            
            config.listeners && mif.on(config.listeners);
            
            if(!!config.html){
                mif.update(config.html);
            } else {
                !!config.src && mif.setSrc(config.src);
            }
        }
        
        return mif;   
    };

    /**
     * Internal Error class for ManagedIFrame Components
	 * @class Ext.ux.ManagedIFrame.Error
     * @extends Ext.Error
     * @version 2.1.4 
     * @donate <a target="tag_donate" href="http://donate.theactivegroup.com"><img border="0" src="http://www.paypal.com/en_US/i/btn/x-click-butcc-donate.gif" border="0" alt="Make a donation to support ongoing development"></a>
     * @license <a href="http://www.gnu.org/licenses/gpl.html">GPL 3.0</a> 
     * @author Doug Hendricks. Forum ID: <a href="http://extjs.com/forum/member.php?u=8730">hendricd</a> 
     * @copyright 2007-2010, Active Group, Inc. All rights reserved.
	 * @constructor 
     * @param {String} message
     * @param {Mixed} arg optional argument to include in Error object.
	 */
	Ext.ux.ManagedIFrame.Error = Ext.extend(Ext.Error, {
	    constructor : function(message, arg) {
	        this.arg = arg;
	        Ext.Error.call(this, message);
	    },
	    name : 'Ext.ux.ManagedIFrame'
	});
    
	Ext.apply(Ext.ux.ManagedIFrame.Error.prototype, {
	    lang: {
	        'documentcontext-remove': 'An attempt was made to remove an Element from the wrong document context.',
	        'execscript-secure-context': 'An attempt was made at script execution within a document context with limited access permissions.',
	        'printexception': 'An Error was encountered attempting the print the frame contents (document access is likely restricted).'
	    }
	});
    
    /** @private */
    Ext.onReady(function() {
            // Generate CSS Rules but allow for overrides.
            var CSS = new Ext.ux.ManagedIFrame.CSS(document), rules = [];

            CSS.getRule('.ux-mif-fill')|| (rules.push('.ux-mif-fill{height:100%;width:100%;}'));
            CSS.getRule('.ux-mif-mask-target')|| (rules.push('.ux-mif-mask-target{position:relative;zoom:1;}'));
            CSS.getRule('.ux-mif-el-mask')|| (rules.push(
              '.ux-mif-el-mask {z-index: 100;position: absolute;top:0;left:0;-moz-opacity: 0.5;opacity: .50;*filter: alpha(opacity=50);width: 100%;height: 100%;zoom: 1;} ',
              '.ux-mif-el-mask-msg {z-index: 1;position: absolute;top: 0;left: 0;border:1px solid;background:repeat-x 0 -16px;padding:2px;} ',
              '.ux-mif-el-mask-msg div {padding:5px 10px 5px 10px;border:1px solid;cursor:wait;} '
              ));


            if (!CSS.getRule('.ux-mif-shim')) {
                rules.push('.ux-mif-shim {z-index:8500;position:absolute;top:0px;left:0px;background:transparent!important;overflow:hidden;display:none;}');
                rules.push('.ux-mif-shim-on{width:100%;height:100%;display:block;zoom:1;}');
                rules.push('.ext-ie6 .ux-mif-shim{margin-left:5px;margin-top:3px;}');
            }
            
            if (!CSS.getRule('.x-hide-nosize')){ 
                rules.push ('.x-hide-nosize{height:0px!important;width:0px!important;visibility:hidden!important;border:none!important;zoom:1;}.x-hide-nosize * {height:0px!important;width:0px!important;visibility:hidden!important;border:none!important;zoom:1;}');
            }
  
            !!rules.length && CSS.createStyleSheet(rules.join(' '), 'mifCSS');
            
        });

    /** @sourceURL=<mif.js> */
    Ext.provide && Ext.provide('mif');
})();/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext,window*/
function utils_logout(reload) {
    if (Ext.isEmpty(reload)) {
        reload = true;
    }
    Ext.util.Cookies.set('userLogin', '');
    Ext.util.Cookies.clear('userLogin');
    Ext.util.Cookies.set('hashCode', '');
    Ext.Ajax.defaultHeaders.Authorization = '';
    if (reload) {
        window.location.reload();
    }	
	    
}
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n,document, window, SitoolsDesk*/
Ext.namespace('sitools.widget');

/**
 * @cfg {string} urlFeed The feed URL
 * @cfg {string} feedType the type of the feed ("atom_1.0" or "rss_2")
 * @cfg {string} feedSource the source of the feed (OPENSEARCH or CLASSIC)
 * @requires sitools.user.component.openSearchResultFeed
 */
sitools.widget.FeedGridFlux = function (config) {
    
    this.datasetName = config.datasetName;
    function clickOnRow(self, rowIndex, e) {
        e.stopEvent();
        var rec = self.store.getAt(rowIndex);
        if (Ext.isEmpty(rec)) {
            return;
        }
        // si on est pas sur le bureau
        if (Ext.isEmpty(window) || Ext.isEmpty(window.SitoolsDesk)) {
            var component = new sitools.widget.feedItemDetails({
                record : rec
            });
            var win = new Ext.Window({
                stateful : false,
                title : i18n.get('label.viewFeedDetail'),
                width : 400,
                height : 600,
                shim : false,
                animCollapse : false,
                constrainHeader : true,
                layout : 'fit',
                modal : true
            });
            win.add(component);
            win.show();
        } else {
            var componentCfg = {
                record : rec
            };
            var jsObj = sitools.widget.feedItemDetails;

            var windowConfig = {
                id : "viewFeedDetail",
                title : i18n.get('label.viewFeedDetail'),
                saveToolbar : false
            };
            SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, jsObj, true);

        }
    }

    Ext.apply(this);
    this.layout = "fit";
    this.urlFeed = config.urlFeed;
    
    var gridPanel;
    if (config.feedSource !== undefined && config.feedSource === "OPENSEARCH") {
        gridPanel = new sitools.user.component.openSearchResultFeed(config);
    } else {
        config.listeners = {
            rowdblclick : clickOnRow
        };
        if (config.feedType !== undefined && config.feedType === "atom_1.0") {
            gridPanel = new sitools.widget.atom1FeedReader(config);
        } else {
            gridPanel = new sitools.widget.rss2FeedReader(config);
        }
    }

    this.btnSubscribeRss = new Ext.Button({
        text : i18n.get('label.subscribeRss'),
        cls : 'services-toolbar-btn',
        icon : loadUrl.get('APP_URL') + '/common/res/images/icons/rss.png',
        handler : this.subscribeRss
     });
     
     this.bbar = {
         xtype : 'toolbar',
         cls : "services-toolbar", 
         defaults : {
             scope : this
         },
         items : [ this.btnSubscribeRss ]
     };
    
    this.items = [ gridPanel ];

    sitools.widget.FeedGridFlux.superclass.constructor.call(this);
};

Ext.extend(sitools.widget.FeedGridFlux, Ext.Panel, {
    componentType : "feeds",
    _getSettings : function () {
        return {
        	objectName : "feedsReader"
        };
    },
    
    subscribeRss : function () {
        window.open(this.urlFeed, '_blank');
    },
    border : false

});

Ext.reg('appfeedgridflux', sitools.widget.FeedGridFlux);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n,document,window,SitoolsDesk*/
Ext.namespace('sitools.widget');

/**
 * @param urlFeed :
 *            The feed URL
 */
sitools.widget.rss2FeedReader = function (config) {
    Ext.apply(this);
    this.layout = "fit";
    this.storeFeedsRecords = new Ext.data.Store({
        autoLoad : true,
        sortInfo : {field : 'pubDate', direction : "DESC"},
        proxy : new Ext.data.HttpProxy({
            url : config.urlFeed,
            restful : true,
            listeners : {
                scope : this,
                exception : onRequestFeedException
            }
        }),
        reader : new Ext.data.XmlReader({
            record : 'item'
        }, [ 'title', 'author', {
            name : 'pubDate',
            type : 'date'
        }, 'link', 'description', 'content', 'guid', {
        	name : 'imageUrl',
        	mapping : "enclosure@url"
        }, {
        	name : 'imageType',
        	mapping : "enclosure@type"
        }])
    });

    var columns = [ {
        id : 'image',
        header : "Image",
        dataIndex : 'imageUrl',
        sortable : false,
        width : 120
        ,
        renderer : this.imageRenderer
    }, {
        id : 'title',
        header : "Title",
        dataIndex : 'title',
        sortable : true,
        width : 460,
        scope : this,
        renderer : this.formatTitle
    }, {
        header : "Author",
        dataIndex : 'author',
        width : 100,
        hidden : true,
        sortable : true
    }, {
        id : 'last',
        header : "Date",
        dataIndex : 'pubDate',
        width : 150,
        renderer : this.formatDate,
        sortable : true,
        hidden : true
    } ];
    
    sitools.widget.rss2FeedReader.superclass.constructor.call(this, {
        // height : 300,
        columns : columns,
        store : this.storeFeedsRecords,
        loadMask : {
            msg : i18n.get("label.loadingFeed")
        },
        sm : new Ext.grid.RowSelectionModel({
            singleSelect : true
        }),
        autoExpandColumn : 'title',
        hideHeaders : true,
        viewConfig : {
            forceFit : true,
            enableRowBody : true,
            showPreview : true,
            getRowClass : this.applyRowClass
        },
        listeners : config.listeners
        
    });

    // this.on('rowcontextmenu', this.onContextClick, this);
    // this.on('beforeShow',this.loadData);
};

Ext.extend(sitools.widget.rss2FeedReader, Ext.grid.GridPanel, {

   
    loadData : function () {
        this.loadFeed('http://feeds.feedburner.com/extblog');
        this.doLayout();
    },

    loadFeed : function (url) {
        this.store.baseParams = {
            feed : url
        };
        this.store.load();
    },

    togglePreview : function (show) {
        this.view.showPreview = show;
        this.view.refresh();
    },

    // within this function "this" is actually the GridView
    applyRowClass : function (record, rowIndex, p, ds) {
        if (this.showPreview) {
            var xf = Ext.util.Format;
            //p.body = '<p class=sous-titre-flux>' + record.data.description + '</p>';
            p.body = '<p class=sous-titre-flux>' + xf.ellipsis(xf.stripTags(record.data.description), 300) + '</p>';
            return 'x-grid3-row-expanded';
        }
        return 'x-grid3-row-collapsed';
    },

    formatDate : function (date) {
        if (!date) {
            return '';
        }
        var now = new Date();
        var d = now.clearTime(true);
        if (date instanceof Date){
            var notime = date.clearTime(true).getTime();
            if (notime == d.getTime()) {
                return 'Today ' + date.dateFormat('g:i a');
            }
            d = d.add('d', -6);
            if (d.getTime() <= notime) {
                return date.dateFormat('D g:i a');
            }
            return date.dateFormat('n/j g:i a');
        }
        else {
            return date;
        }
    },

    formatTitle : function (value, p, record) {
        var link = record.data.link;
        var xf = Ext.util.Format;
        var author = (Ext.isEmpty(record.data.author)) ? "" : record.data.author;
        var dateFormat = this.formatDate(record.data.pubDate);
        var res = "";
        if (link !== undefined && link !== "") {
            res = String.format('<div class="topic"><a href="{0}" title="{1}" target="_blank"><span class="rss_feed_title">{2}</span></a><br/><span class="author">{3}</span></div>', link, value, 
                    xf.ellipsis(xf.stripTags(value), 50), author);
        } else {
            res = String.format('<div class="topic"><span class="rss_feed_title">{0}</span><br/><span class="author">{1}</span></div>', xf.ellipsis(xf.stripTags(value), 50), author);
        }
        if (dateFormat != "" && dateFormat != null ){
            res += String.format('<p id="feeds-date">{0}</p>', dateFormat);
        }
        return res;
    }, 
    
    imageRenderer : function (value, p, record) {
    	if (Ext.isEmpty(value) || Ext.isEmpty(record.data.imageType)) {
            return "";
        }
        if (record.data.imageType.substr(0, 5) != "image") {
        	return "";
        }
		return String.format('<img src="{0}" width="50px">', value);
    },
    
    sortByDate : function (direction){
        this.storeFeedsRecords.sort('pubDate', direction);
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n,document*/
Ext.namespace('sitools.widget');

/**
 * Displays a grid of atom1 format feeds
 * @class sitools.widget.atom1FeedReader
 * @extends Ext.grid.GridPanel
 * @cfg {string} datasetId The Dataset id,
 * @cfg {string} urlFeed The url to request feed
 * @cfg {string} datasetName The dataset name
 * @cfg {string} feedSource
 * @cfg {boolean} autoLoad store configuration
 */
sitools.widget.atom1FeedReader = function (config) {
	Ext.apply(this);
	this.layout = "fit";
	this.storeFeedsRecords = new Ext.data.Store({
        autoLoad : true,
        sortInfo : {field : 'pubDate', direction : "DESC"},
	    proxy : new Ext.data.HttpProxy({
	        url : config.urlFeed,
	        restful : true,
            listeners : {
                scope : this,
                exception : onRequestFeedException
            }
	    // url : 'http://extjs.com/forum/external.php?type=RSS2'
	    }),
	    reader : new Ext.data.XmlReader({
            record : 'entry'
        }, [ 'title',
             {
                name : 'author', 
                mapping : "author.name"
             }, {
            name : 'pubDate',
            mapping : 'updated',
            type : 'date'
          }, {
              name : 'link',
              mapping: "link@href"
             },
             { 
                 name : 'description',
                 mapping : 'content'
             },
             'content',
        	{
               name : 'imageUrl',
            	createAccessor : function (data, field) {
            		var q = Ext.DomQuery;
            		// select node link with attribute type like image%
            		var node = q.selectNode("link[type^=image]", data);
            		var result = {};
            		if (Ext.isEmpty(node)) {
            			return result;
            		}
            		Ext.each(node.attributes, function (attribute) {
            			result[attribute.name] = attribute.value;
            		});
            		return result;
            	}
        	}
        ])

	});

	var columns = [ {
        id : 'image',
        header : "Image",
        dataIndex : 'imageUrl',
        sortable : false,
        width : 120
        ,
        renderer : this.imageRenderer
    }, {
        id : 'title',
        header : "Title",
        dataIndex : 'title',
        sortable : true,
        width : 460,
        scope : this,
        renderer : this.formatTitle
    }, {
        header : "Author",
        dataIndex : 'author',
        width : 100,
        hidden : true,
        sortable : true
    }, {
        id : 'last',
        header : "Date",
        dataIndex : 'pubDate',
        width : 150,
        renderer : this.formatDate,
        sortable : true,
        hidden : true
    } ];

	sitools.widget.atom1FeedReader.superclass.constructor.call(this, {
	    // height : 300,
	    columns : columns,
	    store : this.storeFeedsRecords,
	    loadMask : {
            msg : i18n.get("label.loadingFeed")
        },
	    sm : new Ext.grid.RowSelectionModel({
		    singleSelect : true
	    }),
	    autoExpandColumn : 'title',
	    hideHeaders : true,
	    viewConfig : {
	        forceFit : true,
	        enableRowBody : true,
	        showPreview : true,
	        getRowClass : this.applyRowClass
	    },
        listeners : config.listeners
	});
};

Ext.extend(sitools.widget.atom1FeedReader, Ext.grid.GridPanel, {
    /**
     * Load the feeds with the given url
     * @param {string} url
     */
    loadFeed : function (url) {
        this.store.baseParams = {
            feed : url
        };
        this.store.load();
    },

    /**
     * switch from preview to complete view
     * @param {boolean} show
     */
    togglePreview : function (show) {
        this.view.showPreview = show;
        this.view.refresh();
    },

    /**
     * override the method getRowClass 
     * @param {Record} record The {@link Ext.data.Record} corresponding to the current row.
     * @param {Number} index The row index.
     * @param {Object} rowParams A config object that is passed to the row template during rendering that allows
     * customization of various aspects of a grid row.
     * <p>If {@link #enableRowBody} is configured <b><tt></tt>true</b>, then the following properties may be set
     * by this function, and will be used to render a full-width expansion row below each grid row:</p>
     * <ul>
     * <li><code>body</code> : String <div class="sub-desc">An HTML fragment to be used as the expansion row's body content (defaults to '').</div></li>
     * <li><code>bodyStyle</code> : String <div class="sub-desc">A CSS style specification that will be applied to the expansion row's &lt;tr> element. (defaults to '').</div></li>
     * </ul>
     * The following property will be passed in, and may be appended to:
     * <ul>
     * <li><code>tstyle</code> : String <div class="sub-desc">A CSS style specification that willl be applied to the &lt;table> element which encapsulates
     * both the standard grid row, and any expansion row.</div></li>
     * </ul>
     * @param {Store} store The {@link Ext.data.Store} this grid is bound to
     */
    applyRowClass : function (record, rowIndex, p, ds) {
        if (this.showPreview) {
            var xf = Ext.util.Format;
            if (record.data.summary != "" && record.data.summary != undefined){
                p.body = '<p class=sous-titre-flux>' + xf.ellipsis(xf.stripTags(record.data.summary), 300) + '</p>';
                return 'x-grid3-row-expanded';
            }
        }
        return 'x-grid3-row-collapsed';
    },

    /**
     * Custom date format
     * @param {Date} date the input date
     * @return {String} the date formated
     */
    formatDate : function (date) {
        if (!date) {
            return '';
        }
        var now = new Date();
        var d = now.clearTime(true);
        if (date instanceof Date){
            var notime = date.clearTime(true).getTime();
            if (notime == d.getTime()) {
                return 'Today ' + date.dateFormat('g:i a');
            }
            d = d.add('d', -6);
            if (d.getTime() <= notime) {
                return date.dateFormat('D g:i a');
            }
            return date.dateFormat('n/j g:i a');
        }
        else {
            return date;
        }
    },

    /**
     * Custom renderer for title columns
     * @param {} value the value to format
     * @param {} p
     * @param {Ext.data.Record} record
     * @return {String} The title value formatted.
     */
    formatTitle : function (value, p, record) {
        var author = (record.data.author.name !== undefined) ? record.data.author.name : "";
        var link = record.data.link;
        var xf = Ext.util.Format;
        var dateFormat = this.formatDate(record.data.updated);
        var author = (record.data.author.name !== undefined) ? record.data.author.name : "";
        var authorEmail = (record.data.author.email !== undefined) ? record.data.author.email : "";
        var res = "";
        if (link !== undefined && link !== "") {
            res = String.format('<div class="topic"><a href="{0}" title="{1}" target="_blank"><span class="rss_feed_title">{2}</span></a><br/><span class="author">{3}</span></div>', link, value, 
                    xf.ellipsis(xf.stripTags(value), 50), author);
        } else {
            res = String.format('<div class="topic"><span class="rss_feed_title">{0}</span><br/><span class="author">{1}</span></div>', xf.ellipsis(xf.stripTags(value), 50), author);
        }
        if (dateFormat != "" && dateFormat != undefined ){
            res += String.format('<p id="feeds-date">{0}</p>', dateFormat);
        }
        return res;

    }, 
    imageRenderer : function (value, p, record) {
    	if (Ext.isEmpty(value) || Ext.isEmpty(value.href)) {
            return "";
        }
        if (value.type.substr(0, 5) != "image") {
        	return "";
        }
		return String.format('<img src="{0}" width="50px">', value.href);
    },
    
    sortByDate : function (direction){
        this.storeFeedsRecords.sort('pubDate', direction);
    }

});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n,document*/
Ext.namespace('sitools.widget');

/**
 * @param urlFeed :
 *            The feed URL
 */
sitools.widget.feedItemDetails = Ext.extend(Ext.Panel, {

    initComponent : function () {

        this.layout = "fit";

        var record = this.record;
        
        if (!Ext.isEmpty(record)) {
            
            this.store = new Ext.data.JsonStore({
                idProperty: 'title',
                fields: [
                    {name : 'title'},
                    {name : 'pubDate', type: 'date', dateFormat: 'timestamp'},
                    {name : 'published', type: 'date', dateFormat: 'timestamp'},
                    {name : 'author'}, 
                    {name : 'link'},
                    {name : 'description'},
                    {name : 'imageUrl'},
                    {name : 'image'}
                ],
                listeners : {
                    scope : this,
                    add : function (store, records, ind){
                        if (record.data.imageUrl == undefined && record.data.image != undefined){
                            record.data.image = record.data.imageUrl;
                        }
                        if (records[0].data.pubDate != ""){
                            records[0].data.pubDate = this.formatDate(records[0].data.pubDate);
                        }
                    }
                }
            });
            
            this.store.add(record);
            
            this.tpl = new Ext.XTemplate(
                    '<tpl for=".">',
                        '<div class="feed-article">',
                            '<tpl if="this.isDisplayable(imageUrl)">',
                                '<div class="feed-img">',
                                    '<img src="{imageUrl}" title="{title}" width="70" height="70"/>',
                                '</div>',
                            '</tpl>',
                            '<p class="feed-title"> {title} </p>',
                            '<tpl if="this.isDisplayable(pubDate)">',
                                '<div class="feed-date-detail">',
                                    '<b> Date : </b> {pubDate} ',
                                '</div>',
                            '</tpl>',
                            '<tpl if="this.isDisplayable(author)">',
                                '<div class="feed-author">',
                                    '<b> Author : </b> {author} ',
                                '</div>',
                            '</tpl>',
                            '<div class="feed-description">',
                                '{description}',
                            '</div>',
                            '<div class="feed-complementary">',
                                '<p style="padding-bottom: 3px;"> <b> Link : </b> <a href="{link}" target="_blank" title="{title}">{link}</a> </p>',
                                '<tpl if="this.isDisplayable(imageUrl)">',
                                    '<p> <b> Image Url : </b> <a href="{imageUrl}" target="_blank">{imageUrl}</a> </p>',
                                '</tpl>',
                            '</div>',
                        '</div>',
                    '</tpl>',
                    {
                        compiled : true,
                        isDisplayable : function (item) {
                            if (item != "" && item != undefined){
                                return true;
                            }
                            else {
                                return false;
                            }
                        }
                    }
            );
            
            this.feedsDataview = new Ext.DataView({
              id: 'detailFeed-view',
              autoScroll : true,
              layout: 'fit',
              store : this.store,
              tpl : this.tpl,
              cls : 'detailFeed-view',
              emptyText: i18n.get('label.nothingToDisplay')
            });

            this.componentType = 'feedDetails';
            this.items = [ this.feedsDataview ];
        }

        sitools.widget.feedItemDetails.superclass.initComponent.call(this);
    },
    
    formatDate : function (date) {
        if (!date) {
            return '';
        }
        var now = new Date();
        var d = now.clearTime(true);
        if (date instanceof Date){
            var notime = date.clearTime(true).getTime();
            if (notime == d.getTime()) {
                return 'Today ' + date.dateFormat('g:i a');
            }
            d = d.add('d', -6);
            if (d.getTime() <= notime) {
                return date.dateFormat('D g:i a');
            }
            return date.dateFormat('n/j g:i a');
        }
        else {
            return date;
        }
    }, 
    /**
     * Method called when trying to show this component with fixed navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInFixedNav : function (me, config) {
        Ext.apply(config.windowSettings, {
            width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
            height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
        });
        SitoolsDesk.openModalWindow(me, config);
    }, 
    /**
     * Method called when trying to show this component with Desktop navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInDesktopNav : function (me, config) {
        Ext.apply(config.windowSettings, {
            width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
            height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
        });
        SitoolsDesk.openModalWindow(me, config);
    }
    
    
    
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
Ext.namespace("Ext.ux");
Ext.ux.NotificationMgr = {
positions: []
};
Ext.ux.Notification = Ext.extend(Ext.Window, {
    initComponent: function(){
        Ext.apply(this, {
            iconCls: this.iconCls || 'x-icon-information',
            cls: 'x-notification',
            width: 200,
            autoHeight: true,
            plain: false,
            draggable: false,
            shadow:false,
            bodyStyle: 'text-align:center'
        });
        if(this.autoDestroy) {
            this.task = new Ext.util.DelayedTask(this.hide, this);
        } else {
            this.closable = true;
        }
        Ext.ux.Notification.superclass.initComponent.apply(this);
    },
    setMessage: function(msg){
        this.body.update(msg);
    },
    setTitle: function(title, iconCls){
        Ext.ux.Notification.superclass.setTitle.call(this, title, iconCls||this.iconCls);
    },
    onDestroy: function(){
        Ext.ux.NotificationMgr.positions.remove(this.pos);
        Ext.ux.Notification.superclass.onDestroy.call(this);   
    },
    cancelHiding: function(){
        this.addClass('fixed');
        if(this.autoDestroy) {
            this.task.cancel();
        }
    },
    afterShow: function(){
        Ext.ux.Notification.superclass.afterShow.call(this);
        Ext.fly(this.body.dom).on('click', this.cancelHiding, this);
        if(this.autoDestroy) {
            this.task.delay(this.hideDelay || 5000);
       }
    },
    animShow: function(){
        this.pos = 0;
        while(Ext.ux.NotificationMgr.positions.indexOf(this.pos)>-1)
            this.pos++;
        Ext.ux.NotificationMgr.positions.push(this.pos);
        this.setSize(200,100);
        this.el.alignTo(document, "br-br", [ -20, -140-((this.getSize().height+10)*this.pos) ]);
        this.el.slideIn('b', {
            duration: 1,
            callback: this.afterShow,
            scope: this
        });
    },
    animHide: function(){
        this.el.ghost("b", {
            duration: 1,
            remove: false,
            callback : function () {
                Ext.ux.NotificationMgr.positions.remove(this.pos);
                this.destroy();
            }.createDelegate(this)

        });
    },
    focus: Ext.emptyFn
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/

/**  (c) 2007-2008 Timo Michna / www.matikom.de
*  All rights reserved
*
*  This script is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 3 of the License, or
*  (at your option) any later version.
*
*  The GNU General Public License can be found at
*  http://www.gnu.org/copyleft/gpl.html.
*
*
*  This script is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  This copyright notice MUST APPEAR in all copies of the script!
***************************************************************/

/***************************************************************
*  For commercial use, ask the author for permission and different license
***************************************************************/


Ext.namespace('Ext.ux');
Ext.namespace('Ext.ux.Plugin');

Ext.ux.Plugin.LiteRemoteComponent = function (config){
	var defaultType = config.xtype || 'panel';
    var callback = function(res){ 
		this.container.add(Ext.ComponentMgr.create(Ext.decode(res.responseText), defaultType)).show();
		this.container.doLayout() ;
	};
    return{
		init : function (container){
			this.container = container;
			Ext.Ajax.request(Ext.apply(config, {success: callback, scope: this}));
    	}
	}
};

/**
 * @author Timo Michna / matikom
 * @class Ext.ux.Plugin.RemoteComponent
 * @extends Ext.util.Observable
 * @constructor
 * @param {Object} config
 * @version 0.3.0
 * Plugin for Ext.Container/Ext.Toolbar Elements to dynamically 
 * add Components from a remote source to the Element�s body.  
 * Loads configuration as JSON-String from a remote source. 
 * Creates the Components from configuration.
 * Adds the Components to the Container body.
 * Additionally to its own config options the class accepts all the 
 * configuration options required to configure its internal Ext.Ajax.request().
 */
Ext.ux.Plugin.RemoteComponent = function (config){

   /**
    * @cfg {String} breakOn 
	* set to one of the plugins events, to stop any 
    * further processing of the plugin, when the event fires.
    */
   /**
    * @cfg {mixed} loadOn 
	* Set to one of the Containers events {String}, to defer 
    * further processing of the plugin to when the event fires.
	* Set as an object literal {event: 'event', scope: 'scope'}
    * to listen for a different components (not the container) event.
    * Set to an numeric Array to listen to different events or components.
    * Use String or Literal style in numeric Array. Plugin will load by
	* the first occurence of any of the events. 
    */
   /**
	* @cfg {String} xtype 
	* Default xtype for loaded toplevel component.
	* Overwritten by config.xtype or xtype declaration 
	* Defaults to 'panel'
	* in loaded toplevel component.
	*/
   /**
	* @cfg {Boolean} purgeSubscribers 
	* set to 'true' to avoid unsubstribing all listeners after successfull process chain 
	* Defaults to false
	*/
   /**
	* @cfg {Mixed el} mask 
	* The element or DOM node, or its id to mask with loading indicator  
	*/
   /**
	* @cfg {Object} maskConfig 
	* Configuration for LoadMask.
	* only effective if config option 'mask' is set.    
	*/
	var defaultType = config.xtype || 'panel';
	Ext.applyIf(config, {
		purgeSubscribers:true
	});
	this.initialConfig = config;
    Ext.apply(this, config);
    //this.purgeSubscribers = config.purgeSubscribers || true;
    this.addEvents({
	    /**
	     * @event beforeload
	     * Fires before AJAX request. Return false to stop further processing.
	     * @param {Object} config
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'beforeload' : true,
	    /**
	     * @event beforecreate
	     * Fires before creation of new Components from AJAX response. 
		 * Return false to stop further processing.
	     * @param {Object} JSON-Object decoded from AJAX response
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'beforecreate' : true,
	    /**
	     * @event beforeadd
	     * Fires before adding the new Components to the Container. 
		 * Return false to stop further processing.
	     * @param {Object} new Components created from AJAX response.
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'beforeadd' : true,
	    /**
	     * @event beforecomponshow
	     * Fires before show() is called on the new Components. 
		 * Return false to stop further processing.
	     * @param {Object} new Components created from AJAX response.
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'beforecomponshow': true,
	    /**
	     * @event beforecontainshow
	     * Fires before show() is called on the Container. 
		 * Return false to stop further processing.
	     * @param {Object} new Components created from AJAX response.
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'beforecontainshow': true,
	    /**
	     * @event success
	     * Fires after full process chain. 
		 * Return false to stop further processing.
	     * @param {Object} new Components created from AJAX response.
	     * @param {Ext.ux.Plugin.RemoteComponent} this
	     */
        'success': true
    });
	Ext.ux.Plugin.RemoteComponent.superclass.constructor.call(this, config);
	// set breakpoint 
	if(config.breakOn){
	 	this.on(config.breakOn, function(){return false;});
	}
   /**
    * private
    * method adds component to container.
    * Creates Components from responseText and  
    * and populates Components in Container.
    * @param {Object} JSON Config for new component.
    */
	var renderComponent = function(JSON){
		if(this.fireEvent('beforeadd', JSON, this)){
			//this.container.initComponent();
			var component = this.container.add(JSON);
			
			component.fireEvent ('bodyResize', this);
			//alert (this.container.ownerCt.height());
			if(this.fireEvent('beforecomponshow', component, this)){
				return component;	
			} 				
		} 
	}.createDelegate(this);
   /**
    * private
    * Callback method for successful Ajax request.
    * Creates Components from responseText and  
    * and populates Components in Container.
    * @param {Object} response object from successful AJAX request.
    */
    var callback = function(res){ 
        var JSON = Ext.decode(res.responseText);
		if(this.fireEvent('beforecreate', JSON, this)){
			var component = null;
			//JSON = JSON instanceof Array ? JSON[0] : JSON;
			if(JSON instanceof Array){
				Ext.each(JSON, function(j, i){
						component = renderComponent(j).show();;
				});			
			}else{
				component = renderComponent(JSON).show();
			}
			if(this.fireEvent('beforecontainshow', component, this)){
				this.container.ownerCt.doLayout();
				this.fireEvent('success', component, this);
			} 				
		}   
		if(this.purgeSubscribers){
			this.purgeListeners();				
		}
	}.createDelegate(this);
   /**
    * public
    * Processes the AJAX request.
    * Generally only called internal. Can be called external,
    * when processing has been stopped or defered by config
    * options breakOn or loadOn.
    */
	this.load = function(){
		if(this.fireEvent('beforeload', config, this)){
			if(config.mask){
				var mask = new Ext.LoadMask(Ext.getDom(config.mask), Ext.apply({msg:'loading components...'}, config.maskConfig || {}));	
				mask.show();
				this.on('success', mask.hide, mask);
			}
			Ext.Ajax.request(Ext.apply(config, {success: callback, scope: this}));				
		} 
	};
   /**
    * public
    * Initialization method called by the Container.
    */
    this.init = function (container){
		container.on('beforedestroy', function(){this.purgeListeners();}, this);
		this.container = container;
		if(config.loadOn){		 	
			if(config.loadOn instanceof Array){
				Ext.each(config.loadOn, function(l, i, a){
					var evt = l.event || l.loadOn;
					var defer = function (){
						this.load();
						Ext.each(a, function(lo){
							(lo.scope || container).un(evt, defer, this);	
						}.createDelegate(this));
					}.createDelegate(this);
					(l.scope || container).on(evt, defer, this);					
				}.createDelegate(this));
			}else{
				(config.loadOn.scope || container).on((config.loadOn.event || config.loadOn), this.load, this, {single:true});							
			}
		}else{
			this.load();	
		}           
    };
};
Ext.extend(Ext.ux.Plugin.RemoteComponent, Ext.util.Observable);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, setTimeout*/
/*!
 * Ext JS Library 3.2.1
 * Copyright(c) 2006-2010 Ext JS, Inc.
 * licensing@extjs.com
 * http://www.extjs.com/license
 */
Ext.ux.Portal = Ext.extend(Ext.Panel, {
    layout : 'column',
    autoScroll : true,
    cls : 'x-portal',
    defaultType : 'portalcolumn',
    resizable : true,

    initComponent : function () {
	    Ext.ux.Portal.superclass.initComponent.call(this);
	    this.addEvents({
	        validatedrop : true,
	        beforedragover : true,
	        dragover : true,
	        beforedrop : true,
	        drop : true
	    });
    },

    initEvents : function () {
	    Ext.ux.Portal.superclass.initEvents.call(this);
	    this.dd = new Ext.ux.Portal.DropZone(this, this.dropConfig);
    },

    beforeDestroy : function () {
	    if (this.dd) {
		    this.dd.unreg();
	    }
	    Ext.ux.Portal.superclass.beforeDestroy.call(this);
    }
});

Ext.reg('portal', Ext.ux.Portal);

Ext.ux.Portal.DropZone = Ext.extend(Ext.dd.DropTarget, {

    constructor : function (portal, cfg) {
	    this.portal = portal;
	    Ext.dd.ScrollManager.register(portal.body);
	    Ext.ux.Portal.DropZone.superclass.constructor.call(this, portal.bwrap.dom, cfg);
	    portal.body.ddScrollConfig = this.ddScrollConfig;
    },

    ddScrollConfig : {
        vthresh : 50,
        hthresh : -1,
        animate : true,
        increment : 200
    },

    createEvent : function (dd, e, data, col, c, pos) {
	    return {
	        portal : this.portal,
	        panel : data.panel,
	        columnIndex : col,
	        column : c,
	        position : pos,
	        data : data,
	        source : dd,
	        rawEvent : e,
	        status : this.dropAllowed
	    };
    },

    notifyOver : function (dd, e, data) {
	    var xy = e.getXY(), portal = this.portal, px = dd.proxy;

	    // case column widths
	    if (!this.grid) {
		    this.grid = this.getGrid();
	    }

	    // handle case scroll where scrollbars appear during drag
	    var cw = portal.body.dom.clientWidth;
	    if (!this.lastCW) {
		    this.lastCW = cw;
	    } else if (this.lastCW != cw) {
		    this.lastCW = cw;
		    portal.doLayout();
		    this.grid = this.getGrid();
	    }

	    // determine column
	    var col = 0, xs = this.grid.columnX, cmatch = false, len;
	    for (len = xs.length; col < len; col++) {
		    if (xy[0] < (xs[col].x + xs[col].w)) {
			    cmatch = true;
			    break;
		    }
	    }
	    // no match, fix last index
	    if (!cmatch) {
		    col--;
	    }

	    // find insert position
	    var p, match = false, pos = 0, c = portal.items.itemAt(col), items = c.items.items, overSelf = false;

	    for (len = items.length; pos < len; pos++) {
		    p = items[pos];
		    var h = p.el.getHeight();
		    if (h === 0) {
			    overSelf = true;
		    } else if ((p.el.getY() + (h / 2)) > xy[1]) {
			    match = true;
			    break;
		    }
	    }

	    pos = (match && p ? pos : c.items.getCount()) + (overSelf ? -1 : 0);
	    var overEvent = this.createEvent(dd, e, data, col, c, pos);

	    if (portal.fireEvent('validatedrop', overEvent) !== false
	            && portal.fireEvent('beforedragover', overEvent) !== false) {

		    // make sure proxy width is fluid
		    px.getProxy().setWidth('auto');

		    if (p) {
			    px.moveProxy(p.el.dom.parentNode, match ? p.el.dom : null);
		    } else {
			    px.moveProxy(c.el.dom, null);
		    }

		    this.lastPos = {
		        c : c,
		        col : col,
		        p : overSelf || (match && p) ? pos : false
		    };
		    this.scrollPos = portal.body.getScroll();

		    portal.fireEvent('dragover', overEvent);

		    return overEvent.status;
	    } else {
		    return overEvent.status;
	    }

    },

    notifyOut : function () {
	    delete this.grid;
    },

    notifyDrop : function (dd, e, data) {
	    delete this.grid;
	    if (!this.lastPos) {
		    return;
	    }
	    var c = this.lastPos.c, col = this.lastPos.col, pos = this.lastPos.p, panel = dd.panel, dropEvent = this
	            .createEvent(dd, e, data, col, c, pos !== false ? pos : c.items.getCount());

	    if (this.portal.fireEvent('validatedrop', dropEvent) !== false
	            && this.portal.fireEvent('beforedrop', dropEvent) !== false) {

		    dd.proxy.getProxy().remove();
		    panel.el.dom.parentNode.removeChild(dd.panel.el.dom);

		    if (pos !== false) {
			    c.insert(pos, panel);
		    } else {
			    c.add(panel);
		    }

		    c.doLayout();

		    this.portal.fireEvent('drop', dropEvent);

		    // scroll position is lost on drop, fix it
		    var st = this.scrollPos.top;
		    if (st) {
			    var d = this.portal.body.dom;
			    setTimeout(function () {
				    d.scrollTop = st;
			    }, 10);
		    }

	    }
	    delete this.lastPos;
    },

    // internal cache of body and column coords
    getGrid : function () {
	    var box = this.portal.bwrap.getBox();
	    box.columnX = [];
	    this.portal.items.each(function (c) {
		    box.columnX.push({
		        x : c.el.getX(),
		        w : c.el.getWidth()
		    });
	    });
	    return box;
    },

    // unregister the dropzone from ScrollManager
    unreg : function () {
	    Ext.dd.ScrollManager.unregister(this.portal.body);
	    Ext.ux.Portal.DropZone.superclass.unreg.call(this);
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools*/
/*!
 * Ext JS Library 3.2.1
 * Copyright(c) 2006-2010 Ext JS, Inc.
 * licensing@extjs.com
 * http://www.extjs.com/license
 */
Ext.ux.PortalColumn = Ext.extend(Ext.Container, {
    // layout : 'anchor',
    // autoEl : 'div',//already defined by Ext.Component
    defaultType : 'portlet',
    cls : 'x-portal-column'
});

Ext.reg('portalcolumn', Ext.ux.PortalColumn);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*!
 * Ext JS Library 3.2.1
 * Copyright(c) 2006-2010 Ext JS, Inc.
 * licensing@extjs.com
 * http://www.extjs.com/license
 */
/*global Ext, sitools*/
Ext.ux.Portlet = Ext.extend(Ext.Panel, {
    anchor : '100%',
    frame : true,
    collapsible : true,
    draggable : true,
    cls : 'x-portlet',
    // resizer properties
    heightIncrement : 16,
    pinned : false,
    duration : 0.6,
    easing : 'backIn',
    transparent : false,
    minHeight : 10,

    onRender : function (ct, position) {
	    Ext.ux.Portlet.superclass.onRender.call(this, ct, position);

	    // 2008.1.11 xm
	    var createProxyProtoType = Ext.Element.prototype.createProxy;
	    Ext.Element.prototype.createProxy = function (config) {
		    return Ext.DomHelper.append(this.dom, config, true);
	    };

	    this.resizer = new Ext.Resizable(this.el, {
	        animate : true,
	        duration : this.duration,
	        easing : this.easing,
	        handles : 's',
	        transparent : this.transparent,
	        heightIncrement : this.heightIncrement,
	        minHeight : this.minHeight || 100,
	        pinned : this.pinned
	    });
	    this.resizer.on('resize', this.onResizer, this);

	    Ext.Element.prototype.createProxy = createProxyProtoType;
	    // 2008.1.11 xm
    },

    onResizer : function (oResizable, iWidth, iHeight, e) {
	    this.setHeight(iHeight);
    },

    onCollapse : function (doAnim, animArg) {
	    this.el.setHeight('');
	    Ext.ux.Portlet.superclass.onCollapse.call(this, doAnim, animArg);
    }

});

Ext.reg('portlet', Ext.ux.Portlet);
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
/* global Ext, ann */
Ext.namespace('sitools.siteMap');

var loadUrl = {

    map : [],
    /**
     * Load a properties file and and the name/values in a associative array ;
     * Executing this function on multiple properties file increase the size of
     * the array Results can be displayed in the help panel with the display()
     * function
     * 
     * @param url
     *            URL of the i18n file
     * @param callback
     *            No args function that will be executed
     * @returns void
     */
    load : function (url, callback, scope) {

        var siteMapRef = this;
        siteMapRef.transformsPropertiesToMap(url, callback, scope);

    },
    /**
     * Transforms a xml Text to a map
     * 
     * @param text
     *            raw properties file
     * @returns a map (associative array) TODO check when the raw properties
     *          file is rotten
     */
    transformsPropertiesToMap : function (url, callback, scope) {

        var store = new Ext.data.Store({
            proxy : new Ext.data.HttpProxy({
                url : url,
                restful : true
            }),
            reader : new Ext.data.XmlReader({
                record : 'url'
            }, [ {
                name : 'name',
                mapping : 'name'
            }, {
                name : 'loc',
                mapping : 'loc'
            } ])
        });
        var localMap = this.map;

        store.load({
            scope : scope,
            callback : function (r, options, success) {
                var i = 0;
                while (i != undefined) {
                    var rec = r[i];
                    if (rec != undefined) {
                        var url = rec.data.loc;
                        var name = rec.data.name;
                        localMap[name] = url;
                        i++;
                    } else {
                        i = undefined;
                    }
                }
                callback.call(this);
            }
        });
    },
    /**
     * return the url value
     * 
     * @param name
     * @returns
     */
    get : function (entry) {
        return !Ext.isEmpty(this.map[entry]) ? this.map[entry] : entry;
    }
};

/**
 * To be defined
 */
var componentManager = {

    loadedComponents : [],

    load : function (name) {

    }

};

var data = {
    ret : null,
    /**
     * Fetch a html file in the url, and display its content into the helpPanel. *
     * 
     * @param url
     * @returns
     */
    get : function (url, cbk) {
        Ext.Ajax.request({
            method : 'GET',
            url : url,
            success : function (response, opts) {
                cbk(Ext.decode(response.responseText));
            },
            failure : function (response, opts) {
                Ext.Msg.alert("Warning", "Error! Can't get data with url :" + url);
            }
        });
        return this.ret;
    }

};

Ext.applyIf(Array.prototype, {
    clone : function () {
        return [].concat(this);
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, ann, alert, document, alertFailure, getDesktop, SitoolsDesk, locale, portal */
/*global DEFAULT_WIN_HEIGHT, DEFAULT_WIN_WIDTH, sitools, loadUrl, includeJs, DEFAULT_PREFERENCES_FOLDER */

/*
 * @include "desktop/desktop.js"
 * @include "components/columnsDefinition/dependencies/columnsDefinition.js"
 * @include "components/forms/forms.js"
 */

Ext.namespace('sitools.env');
var userPreferences = null;
var userLogin = null;
var sql2ext = {

    map : [],
    load : function (url) {

        var i18nRef = this;
        Ext.Ajax.request({
            method : 'GET',
            url : url,
            // params:'formLogin', using autorization instead
            success : function (response, opts) {
                ann(response.responseText, "no response is sent");
                i18nRef.map = i18nRef.transformsPropertiesToMap(response.responseText);
            },
            failure : function (response, opts) {
                alert("Error! Can't read i18n file with url :" + url);
            }
        });

    },
    /**
     * Transforms a properties Text to a map
     * 
     * @param text
     *            raw properties file
     * @returns a map (associative array) TODO check when the raw properties
     */
    transformsPropertiesToMap : function (text) {
        var array = text.split('\n');
        var localMap = [];
        var i;
        for (i = 0; i < array.length; i++) {
            var string = array[i];
            var indexOfEqualsSign = string.indexOf('=');
            if (indexOfEqualsSign >= 1) {
                var key = string.substring(0, indexOfEqualsSign).replace('\r', '');
                var value = string.substring(indexOfEqualsSign + 1).replace('\r', '');
                localMap[key] = value;
            }
        }
        return localMap;
    },
    /**
     * return the i18n value
     * 
     * @param name
     * @returns
     */
    get : function (entry) {
        return !Ext.isEmpty(this.map[entry]) ? this.map[entry] : 'auto';
    }
};
var i18n = {

    map : [],
    /**
     * Load a properties file and and the name/values in a associative array ;
     * Executing this function on multiple properties file increase the size of
     * the array Results can be displayed in the help panel with the display()
     * function
     * 
     * @param url
     *            URL of the i18n file
     * @param callback
     *            No args function that will be executed
     * @returns void
     */
    load : function (url, callback, loopOnFailure) {
        var i18nRef = this;
        Ext.Ajax.request({
            method : 'GET',
            url : url,
            loopOnFailure : (Ext.isEmpty(loopOnFailure)) ? true : loopOnFailure,
            // params:'formLogin', using autorization instead
            success : function (response, opts) {
                ann(response.responseText, "no response is sent");
                i18nRef.map = i18nRef.transformsPropertiesToMap(response.responseText);
                if (Ext.isFunction(callback)) {
                    callback();
                }
            },
            failure : function (response, opts) {
                if (!opts.loopOnFailure) {
                    Ext.Msg.alert("Error! Can't read i18n file with url :" + url);
                } else {
                    locale.restoreDefault();
                    url = '/sitools/res/i18n/' + locale.getLocale() + '/gui.properties';
                    i18n.load(url, callback, false);
                }
            }
        });

    },
    /**
     * Transforms a properties Text to a map
     * 
     * @param text
     *            raw properties file
     * @returns a map (associative array) TODO check when the raw properties
     *          file is rotten
     */
    transformsPropertiesToMap : function (text) {
        var array = text.split('\n');
        var localMap = [];
        var i;
        for (i = 0; i < array.length; i++) {
            var string = array[i];
            var indexOfEqualsSign = string.indexOf('=');
            if (indexOfEqualsSign >= 1) {
                var key = string.substring(0, indexOfEqualsSign).replace('\r', '');
                var value = string.substring(indexOfEqualsSign + 1).replace('\r', '');
                localMap[key] = value;
            }
        }
        return localMap;
    },
    /**
     * return the i18n value
     * 
     * @param name
     * @returns
     */
    get : function (entry) {
        return !Ext.isEmpty(this.map[entry]) ? this.map[entry] : entry;
    }
};

/**
 * To be defined
 */
var componentManager = {
    loadedComponents : [],
    load : function (name) {

    }
};

var data = {
    ret : null,
    /**
     * Fetch a html file in the url, and display its content into the helpPanel. *
     * 
     * @param url
     * @returns
     */
    get : function (url, cbk) {
        Ext.Ajax.request({
            method : 'GET',
            url : url,
            success : function (response, opts) {
                cbk(Ext.decode(response.responseText));
            },
            failure : function (response, opts) {
                Ext.Msg.alert("Warning", "Error! Can't get data with url :" + url);
            }
        });
        return this.ret;
    }

};
userLogin = Ext.util.Cookies.get('userLogin');
var userStorage = {
	set : function (filename, filepath, content, callback, scope) {
	    userStorage.setData(filename, filepath, content, callback, scope, "json");
    },
    setXML : function (filename, filepath, content, callback, scope) {
        userStorage.setData(filename, filepath, content, callback, scope, "xml");
    },
    //private
    setData : function (filename, filepath, content, callback, scope, type) {
        var config = {
                url : loadUrl.get('APP_URL') + loadUrl.get('APP_USERSTORAGE_USER_URL').replace('{identifier}', userLogin) + "/files",
                method : 'POST',
                scope : scope,
                params : {
                    filepath : filepath,
                    filename : filename
                },
                jsonData : content,
                success : function (ret) {
                    var Json = Ext.decode(ret.responseText);
                    if (!Json.success) {
                        Ext.Msg.alert(i18n.get('label.warning'), Json.message);
                        return;
                    } else {
                        var notify = new Ext.ux.Notification({
                            iconCls : 'x-icon-information',
                            title : i18n.get('label.information'),
                            html : Json.message,
                            autoDestroy : true,
                            hideDelay : 1000
                        });
                        notify.show(document);
                    }
                },
                failure : function () {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('label.warning.savepreference.error'));
                    return;
                },
                callback : callback
            };
        

        if (type === "xml") {
            config.xmlData = content;
        } else {
            config.jsonData = content;
        }
        
        Ext.Ajax.request(config);
    },
    get : function (fileName, filePath, scope, success, failure, callback) {
        Ext.Ajax.request({
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_USERSTORAGE_USER_URL').replace('{identifier}', userLogin) + "/files" + filePath + "/" + fileName,
            method : 'GET',
            scope : scope,
            success : success,
            failure : failure, 
            callback : callback
        });
    }
};

/**
 * Global project variable Used to get the projectId from the url
 */
var projectGlobal = {
    /**
     * Get the current projectId from the url url is like :
     * /sitools/client-user/{projectName}/indexproject.html /sitools/client-user/
     * can be changed
     * 
     * @return the projectId
     */
    projectId : null,
    projectName : null,
    preferences : null,
    userRoles : null, 
    isAdmin : false,
    sitoolsAttachementForUsers : null,
    modules : null,
    links : null,
    callback : Ext.emptyFn,

    initProject : function (callback) {
        this.callback = callback;
        this.projectName = this.getProjectName();
        this.getProjectInfo();
    },

    // only load datasetView used by datasets in the current project
    getDataViewsDependencies : function () {
		Ext.Ajax.request({
            url : this.sitoolsAttachementForUsers + "/datasetViews",
            method : "GET",
            scope : this,
            success : function (ret) {
                var json = Ext.decode(ret.responseText);
                if (!json.success) {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.errorloadingdataviews'));
                    return false;
                } else {
                    var data = json.data;                    
                    Ext.each(data, function (datasetViewComponent) {
                    	if (!Ext.isEmpty(datasetViewComponent.dependencies) && !Ext.isEmpty(datasetViewComponent.dependencies.js)) {
                            Ext.each(datasetViewComponent.dependencies.js, function (dependencies) {
                                includeJs(dependencies.url);
                            }, this);
                        }
                        if (!Ext.isEmpty(datasetViewComponent.dependencies) && !Ext.isEmpty(datasetViewComponent.dependencies.css)) {
							Ext.each(datasetViewComponent.dependencies.css, function (dependencies) {
								includeCss(dependencies.url);
							}, this);
						}
                    });
                    
                }
            },
            callback : function () {
                this.getFormDependencies();
            }
        });   
    }, 
    getFormDependencies : function () {
		Ext.Ajax.request({
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_FORMCOMPONENTS_URL'),
            method : "GET",
            scope : this,
            success : function (ret) {
                var json = Ext.decode(ret.responseText);
                if (!json.success) {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.errorLoadingFormDependencies'));
                    return false;
                } else {
                    var data = json.data;                    
                    Ext.each(data, function (formComponent) {
						includeJs(formComponent.fileUrlUser);
                    });
                }
            },
            callback : function () {
                this.getGUIServicesDependencies();
            }
        });   
    },
    getGUIServicesDependencies : function () {
        Ext.Ajax.request({
            url : this.sitoolsAttachementForUsers + "/guiServices",
            method : "GET",
            scope : this,
            success : function (ret) {
                var json = Ext.decode(ret.responseText);
                if (!json.success) {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.errorLoadingGuiServicesDependencies'));
                    return false;
                } else {
                    var data = json.data;
                    var javascriptDependencies = []
                        Ext.each(data, function (service) {
                            if (!Ext.isEmpty(service.dependencies.js)) {
                                javascriptDependencies = javascriptDependencies.concat(service.dependencies.js);
                            }
                            if (!Ext.isEmpty(service.dependencies.css)) {
                                Ext.each(service.dependencies.css, function (dependencies) {
                                    includeCss(dependencies.url);
                                }, this);
                            }
                        }, this);
                    includeJsForceOrder(javascriptDependencies, 0, this.initLanguages, this);
                }
            }
        });   
    },
    initLanguages : function () {
        Ext.Ajax.request({
            scope : this,
            method : "GET",
            /* /sitools/client-user */
//            url : loadUrl.get('APP_URL') + loadUrl.get('APP_CLIENT_USER_URL') + '/tmp/langues.json',
            url : loadUrl.get('APP_URL') + '/client-user/tmp/langues.json',
            success : function (response) {
                var json = Ext.decode(response.responseText);
	            this.languages = json.data;
            },
            failure : function (response) {
                Ext.Msg.alert('Status', i18n.get('warning.serverError'));
            }, 
            callback : function () {
                this.getPreferences(this.callback);
            }
        });
    },
    getUserRoles : function (cb) {
		if (Ext.isEmpty(userLogin)) {
			cb.call();
		} 
		else {
			Ext.Ajax.request({
	            url : loadUrl.get('APP_URL') + loadUrl.get("APP_USER_ROLE_URL"),
	            method : "GET",
	            scope : this,
	            success : function (ret) {
	                var json = Ext.decode(ret.responseText);
	                if (!json.success) {
	                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.errorGettingUserRoles'));
	                    return false;
	                } else {
						this.user = json.user;        
						if (Ext.isEmpty(this.user.roles)) {
							return;
						}
						for (var index = 0; index < this.user.roles.length; index++) {
							var role = this.user.roles[index];
							if (role.name === "Administrator") {
								this.isAdmin = true;
							}
	                    }
	                }
	            },
	            callback : cb
	        });   
		}
    }, 
    getProjectName : function () {
        if (this.projectName === null) {
            // get the relative url
            var url = document.location.pathname;
            // split the url to get each part of the url in a tab cell
            var tabUrl = url.split("/");

            var i = 0, index;
            var found = false;
            // search for index.html, the projectName is right before
            // '/index.html'
            while (i < tabUrl.length && !found) {
                if (tabUrl[i] === "project-index.html") {
                    found = true;
                    index = i;
                }
                i++;
            }
            // get the projectName from the tabUrl
            this.projectName = tabUrl[index - 1];

            if (this.projectName === undefined || this.projectName === "") {
                Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.noProject'));
            }
        }
        return this.projectName;
    },
    /**
     * Get the name of a project from the server
     */
    getProjectInfo : function () {
        Ext.Ajax.request({
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_PORTAL_URL') + '/projects/' + this.projectName,
            method : "GET",
            scope : this,
            success : function (ret) {
                var data = Ext.decode(ret.responseText);
                if (!data.success) {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.noProjectFound'));
                    return false;
                } else {
                    this.sitoolsAttachementForUsers = data.project.sitoolsAttachementForUsers;
                    this.projectId = data.project.id;
                    this.projectName = data.project.name;
                    this.htmlHeader = data.project.htmlHeader;
                    this.links = data.project.links;
                    this.navigationMode = data.project.navigationMode;
                }
//                var topEl = Ext.get('toppanel');
//                topEl.update(Ext.util.Format.htmlDecode(data.project.htmlHeader));
            },
            callback : function (options, success, response) {
                if (success) {
                    this.getDataViewsDependencies();
                }
            },
            failure : function (response, opts) {
                if (response.status === 403) {
                    Ext.getBody().unmask();
                    Ext.MessageBox.buttonText.ok = i18n.get('label.login');
                    Ext.Msg.show({
                        title : i18n.get('label.information'),
                        msg : i18n.get('label.projectNeedToBeLogged'),
                        width : 350,
                        buttons : Ext.MessageBox.OK,
                        icon : Ext.MessageBox.INFO,
                        fn : function (response) {
                            if (response === 'ok') {
                                sitools.userProfile.LoginUtils.connect({
                                    url : loadUrl.get('APP_URL') + '/login',
                                    register : loadUrl.get('APP_URL') + '/inscriptions/user',
                                    reset : loadUrl.get('APP_URL') + '/resetPassword',
                                    handler : function () {
                                        portal.initAppliPortal({
                                            siteMapRes : loadUrl.get('APP_URL') + loadUrl.get('APP_CLIENT_USER_URL')
                                        });
                                    }
                                });
                            }
                        }
                    });
                }
                else {
                    Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.noProjectError'));
                }
            }
        });
    },    
    getPreferences : function (callback) {
        if (!Ext.isEmpty(userLogin)) {
            var filePath = "/" + DEFAULT_PREFERENCES_FOLDER + "/" + projectGlobal.projectName;
			var fileName = "desktop";
			var success = function (ret) {
                try {
                    this.preferences = Ext.decode(ret.responseText);
	                callback.call();
                } catch (err) {
	                callback.call();
                }
            };
            
            var failure = function (ret) {
                this.getPublicPreferences(callback);
            };
            
            userStorage.get(fileName, filePath, this, success, failure);
        } else {
            this.getPublicPreferences(callback);
        }
    }, 
    getPublicPreferences : function (callback) {
        var AppPublicStorage = loadUrl.get('APP_PUBLIC_STORAGE_URL') + "/files";
        Ext.Ajax.request({
//                url : "/sitools/userstorage/" + userLogin + "/" + DEFAULT_PREFERENCES_FOLDER + "/" + this.projectName + "/desktop?media=json",
            url : loadUrl.get('APP_URL') + AppPublicStorage + "/" + DEFAULT_PREFERENCES_FOLDER + "/" + this.projectName + "/desktop?media=json",
            method : 'GET',
            scope : this,
            success : function (ret) {
                try {
                    this.preferences = Ext.decode(ret.responseText);
                } catch (err) {
                    this.preferences = null;
                }
            }, 
            callback : callback
        });
    }
};

var publicStorage = {
    set : function (filename, filepath, content, callback) {
        this.url = loadUrl.get('APP_URL') + loadUrl.get('APP_PUBLIC_STORAGE_URL') + "/files";
        Ext.Ajax.request({
            url : this.url,
            method : 'POST',
            scope : this,
            params : {
                filepath : filepath,
                filename : filename
            },
            jsonData : content,
            success : function (ret) {
                var Json = Ext.decode(ret.responseText);
                if (!Json.success) {
                    Ext.Msg.alert(i18n.get('label.warning'), Json.message);
                    return;
                } else {
                    var notify = new Ext.ux.Notification({
                        iconCls : 'x-icon-information',
                        title : i18n.get('label.information'),
                        html : Json.message,
                        autoDestroy : true,
                        hideDelay : 1000
                    });
                    notify.show(document);
                }
            },
            failure : function () {
                Ext.Msg.alert(i18n.get('label.warning'), i18n.get('label.warning.savepreference.error'));
                return;
            },
            callback : function () {
                if (!Ext.isEmpty(callback)) {
                    callback.call();
                }
            }
        });

    },
    get : function (fileName, filePath, scope, success, failure) {
        Ext.Ajax.request({
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_PUBLIC_STORAGE_URL') + "/files" + filePath + "/" + fileName,
            method : 'GET',
            scope : scope,
            success : success,
            failure : failure
        });
    }, 
    remove : function () {
        this.url = loadUrl.get('APP_URL') + loadUrl.get('APP_PUBLIC_STORAGE_URL') + "/files" + "?recursive=true";
        Ext.Ajax.request({
            url : this.url,
            method : 'DELETE',
            scope : this,
            success : function (ret) {
                var notify = new Ext.ux.Notification({
                    iconCls : 'x-icon-information',
                    title : i18n.get('label.information'),
                    html : i18n.get("label.publicUserPrefDeleted"),
                    autoDestroy : true,
                    hideDelay : 1000
                });
                notify.show(document);
            },
            failure : function (ret) {
                //cas normal... 
				if (ret.status === 404) {
					var notify = new Ext.ux.Notification({
				        iconCls : 'x-icon-information',
				        title : i18n.get('label.information'),
				        html : i18n.get("label.publicUserPrefDeleted"),
				        autoDestroy : true,
				        hideDelay : 1000
				    });
				    notify.show(document);
				}
				else {
					var notifye = new Ext.ux.Notification({
				        iconCls : 'x-icon-error',
				        title : i18n.get('label.error'),
				        html : ret.responseText,
				        autoDestroy : true,
				        hideDelay : 1000
				    });
				    notifye.show(document);
				}
                
            }
        });
    }
};

function showResponse(ret, notification) {
    try {
        var Json = Ext.decode(ret.responseText);
        if (!Json.success) {
            Ext.Msg.alert(i18n.get('label.warning'), Json.message);
            return false;
        }
        if (notification) {
            var notify = new Ext.ux.Notification({
                iconCls : 'x-icon-information',
                title : i18n.get('label.information'),
                html : Json.message,
                autoDestroy : true,
                hideDelay : 1000
            });
            notify.show(document);
        }
        return true;
    } catch (err) {
        Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.javascriptError') + " : " + err);
        return false;
    }
};
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*!
 * Ext JS Library 3.0+
 * Copyright(c) 2006-2009 Ext JS, LLC
 * licensing@extjs.com
 * http://www.extjs.com/license
 */

/*global Ext, i18n, date, Digest, sql2ext, SitoolsDesk, loadUrl, sitools, showResponse, ColumnRendererEnum, document*/

// GLOBAL BEHAVIOUR
var DEFAULT_NATIVEJSON = false; //must be set to false to constrain Ext.doEncode (if true, doesn't work with prototype library)
var DEFAULT_TIMEOUT = 30000; // server request timeout (msec)
var DEFAULT_TIMEBUF = 10; // time to wait before sending request (msec)
var DEFAULT_NBRETRY = 0;// 3; // nb of request retries (if failure)
var SERVER_OK = 200;
var DEFAULT_WIN_HEIGHT = 400;
var DEFAULT_WIN_WIDTH = 600;
var DEFAULT_WINORDER_WIDTH = 400;
var DEFAULT_ORDER_FOLDER = "dataSelection";
var DEFAULT_PREFERENCES_FOLDER = "preferences";
var DEFAULT_LIVEGRID_BUFFER_SIZE = 300; 
var URL_CGU = "/sitools/res/licences/cgu.html";
var COOKIE_DURATION = 20;
var MULTIDS_TIME_DELAY = 2000;
var SITOOLS_DEFAULT_PROJECT_IMAGE_URL = "/sitools/res/images/sitools2_logo.png";
/**
 * The nearLimit is a
     * parameter for the predictive fetch algorithm within the view. If your
     * bufferSize is small, set this to a value around a third or a quarter of
     * the store's bufferSize (e.g. a value of 25 for a bufferSize of 100;
 */
var DEFAULT_NEAR_LIMIT_SIZE = 100;

Ext.BLANK_IMAGE_URL = '/sitools/cots/extjs/resources/images/default/s.gif';
Ext.USE_NATIVE_JSON  = DEFAULT_NATIVEJSON;
Ext.Ajax.timeout = DEFAULT_TIMEOUT;
var onBeforeRequest = function (conn, options) {
    var date = new Date();
    if (!Ext.isEmpty(Ext.util.Cookies.get('scheme'))) {
		if (Ext.util.Cookies.get('scheme') == "HTTP_Digest") {
			var tmp = null;
			var method = "GET";
			if (!Ext.isEmpty(options.method)) {
				method = options.method;
			}
			var url = options.url;
            if (Ext.isEmpty(options.url) && !Ext.isEmpty(options.scope)) {
                if (!Ext.isEmpty(options.scope.url)) {
                    url = options.scope.url;
                }
            }
			
			var A1 = Ext.util.Cookies.get("A1");
			var auth = new Digest({
				usr : Ext.util.Cookies.get("userLogin"),
				algorithm : Ext.util.Cookies.get("algorithm"),
				realm : Ext.util.Cookies.get("realm"),
				url : url,
				nonce : Ext.util.Cookies.get('nonce'), 
				method : method, 
				mode : "digest", 
				A1 : A1
			});
			Ext.apply(Ext.Ajax.defaultHeaders, {
				Authorization : auth.getDigestAuth()
		    });

		}
		else {
		    if (!Ext.isEmpty(Ext.util.Cookies.get('hashCode'))) {
		        Ext.util.Cookies.set('hashCode', Ext.util.Cookies.get('hashCode'), date.add(Date.MINUTE, COOKIE_DURATION));
		        Ext.apply(Ext.Ajax.defaultHeaders, {
					Authorization : Ext.util.Cookies.get('hashCode')
		        });
		    } else {
		        Ext.apply(Ext.Ajax.defaultHeaders, {
                    Authorization : ''
                });
		    }
		}
    }
    if (!Ext.isEmpty(Ext.util.Cookies.get('userLogin'))) {
        Ext.util.Cookies.set('userLogin', Ext.util.Cookies.get('userLogin'), date.add(Date.MINUTE, COOKIE_DURATION));
    }
};

Ext.Ajax.on('beforerequest', onBeforeRequest, this);

var DEFAULT_LOCALE = "en";
var SITOOLS_DATE_FORMAT = 'Y-m-d\\TH:i:s.u';
var SITOOLS_DEFAULT_IHM_DATE_FORMAT = 'Y-m-d H:i:s.u';

var locale = {
    locale : DEFAULT_LOCALE,
    isInit : false,
    getLocale : function () {
        if (!this.isInit) {
            if (Ext.isEmpty(Ext.util.Cookies.get('language'))) {
                var navigator = window.navigator;
                this.locale = navigator.language || navigator.browserLanguage || navigator.userLanguage;
            }
            else {
                this.locale = Ext.util.Cookies.get('language');
            }
            this.isInit = true;
        }
        return this.locale;                
        
    },
    setLocale : function (locale) {
        this.locale = locale;
    },
    restoreDefault : function () {
        this.setLocale(DEFAULT_LOCALE);
    }
};

var onRequestFeedException = function (proxy, type, action, options, response, args) {
    // si on a un cookie de session et une erreur 403
    if ((response.status == 403) && !Ext.isEmpty(Ext.util.Cookies.get('hashCode'))) {
        Ext.MessageBox.minWidth = 360;
        Ext.MessageBox.alert(i18n.get('label.session.expired'), response.responseText);
    } else {
        Ext.MessageBox.minWidth = 360;
        Ext.MessageBox.alert(i18n.get('label.error'), response.responseText);
    }
    return false;
};

// GLOBAL VARIABLES
var desktop;
var projectGlobal;
var projectId;

// Application d'exception sur tous les JsonStores :
// Ext.override (Ext.data.JsonStore, {
// listeners : {
// exception : function (dataProxy, type, action, options, response){
// Ext.Msg.alert (i18n.get('label.warning'), response.responseText);
// }
// }
// });

// GLOBAL FUNCTIONS
function alertFailure(response, opts) {
	var txt;
	if (response.status == SERVER_OK) {
		var ret = Ext.decode(response.responseText).message;
		txt = i18n.get('msg.error') + ': ' + ret;
	} else {
		txt = i18n.get('warning.serverError') + ': ' + response.statusText;
	}
	Ext.Msg.alert(i18n.get('label.warning'), txt);
// Ext.WindowMgr.bringToFront(alert);
}

function extColModelToJsonColModel(ExtColModel) {
	var colModel = [];
	var columns;
	if (!Ext.isEmpty(ExtColModel.columns)) {
		columns = ExtColModel.columns;
	}
	else {
		columns = ExtColModel;
	}
	Ext.each(columns, function (column) {
	    if (!column.isSelectionModel) {
            colModel.push({
                columnAlias : column.columnAlias,
                dataIndex : column.dataIndexSitools,
                dataIndexSitools : column.dataIndexSitools,
                header : column.header,
                filter : column.filter,
                hidden : column.hidden,
                id : column.id,
                previewColumn : column.previewColumn,
                primaryKey : column.primaryKey,
                schema : column.schema,
                sortable : column.sortable,
                sqlColumnType : column.sqlColumnType,
                tableAlias : column.tableAlias,
                tableName : column.tableName,
                toolTip : column.tooltip,
                urlColumn : column.urlColumn,
                width : column.width,
                // columnAliasDetail : column.columnAliasDetail,
                columnRenderer : column.columnRenderer,
                // datasetDetailId : column.datasetDetailId,
                specificColumnType : column.specificColumnType,
                javaSqlColumnType : column.javaSqlColumnType,
                format : column.format
            //			image : column.image,
            //			datasetDetailUrl : column.datasetDetailUrl

            });
        }
	});
	return colModel;
}

function extColModelToSrv(ExtColModel) {
	var colModel = [];
	var columns;
	if (!Ext.isEmpty(ExtColModel.columns)) {
		columns = ExtColModel.columns;
	}
	else {
		columns = ExtColModel;
	}
	Ext.each(columns, function (column) {
		if (!column.hidden && !column.isSelectionModel) {
			colModel.push(column.columnAlias);
		}
	});
	return colModel.join(", ");
}

function extColModelToStorage(ExtColModel) {
    var colModel = [];
    var columns;
    if (!Ext.isEmpty(ExtColModel.columns)) {
        columns = ExtColModel.columns;
    }
    else {
        columns = ExtColModel;
    }
    Ext.each(columns, function (column) {
        if (!column.hidden && !column.isSelectionModel) {
            colModel.push({
                columnAlias : column.columnAlias, 
                dataIndex : column.dataIndex, 
                dataIndexSitools : column.dataIndexSitools, 
                editor : column.editor, 
                filter : column.filter, 
                header : column.header, 
                hidden : column.hidden, 
                id : column.id, 
                isColumn : column.isColumn, 
                previewColumn : column.previewColumn, 
                primaryKey : column.primaryKey, 
                schema : column.schema, 
                sortable : column.sortable, 
                sqlColumnType : column.sqlColumnType, 
                tableAlias : column.tableAlias, 
                tableName : column.tableName, 
                toolTip : column.tooltip, 
                urlColumn : column.urlColumn, 
                width : column.width, 
//				columnAliasDetail : column.columnAliasDetail,
				columnRenderer : column.columnRenderer, 
//				datasetDetailId : column.datasetDetailId, 
				specificColumnType : column.specificColumnType, 
				javaSqlColumnType : column.javaSqlColumnType,
                unit : column.unit,
                format : column.format
//                image : column.image,
//                datasetDetailUrl : column.datasetDetailUrl
            });
        }
    });
    return colModel;
}
/**
 * Get the Sitools Desktop
 * @returns the sitools Desktop
 */
function getDesktop() {
	if (Ext.isEmpty(this.SitoolsDesk)) {
		return null;
	}
	else {
		return this.SitoolsDesk.app.desktop;
	}
}

/**
 * Get the Sitools Application
 * @returns the sitools Desktop
 */
function getApp() {
	if (Ext.isEmpty(SitoolsDesk)) {
		return null;
	}
	else {
		return SitoolsDesk.app;
	}
}

// Ext.WindowMgr = getDesktop().getManager();
// Override de la méthode initEvents pour que le windowManager utilisé soit
// toujours le même
Ext.override(Ext.Window, {
    initEvents : function () {
	    Ext.Window.superclass.initEvents.call(this);
	    if (this.animateTarget) {
	        this.setAnimateTarget(this.animateTarget);
	    }
	
	    if (this.resizable) {
	        this.resizer = new Ext.Resizable(this.el, {
	            minWidth: this.minWidth,
	            minHeight: this.minHeight,
	            handles: this.resizeHandles || 'all',
	            pinned: true,
	            resizeElement : this.resizerAction,
	            handleCls: 'x-window-handle'
	        });
	        this.resizer.window = this;
	        this.mon(this.resizer, 'beforeresize', this.beforeResize, this);
	    }
	
	    if (this.draggable) {
	        this.header.addClass('x-window-draggable');
	    }
	    this.mon(this.el, 'mousedown', this.toFront, this);
// this.manager = this.manager || Ext.WindowMgr;
	    var tmp = getDesktop();
	    if (Ext.isEmpty(tmp)) {
	        this.manager = Ext.WindowMgr;
	    }
	    else {
		    this.manager = getDesktop().getManager() || Ext.WindowMgr;
	    }
	    this.manager.register(this);
	    if (this.maximized) {
	        this.maximized = false;
	        this.maximize();
	    }
	    if (this.closable) {
	        var km = this.getKeyMap();
	        km.on(27, this.onEsc, this);
	        km.disable();
	    }
	}
});

Ext.override(Ext.grid.GridPanel, {
    stripeRows : true
});

Ext.data.Types.DATEASSTRING = {
	convert : function (v, data) {
		return v;
	}, 
	sortType : function (v) {
		return v;
	}, 
	type : "dateAsString"
	
};


function includeJs(url) {
	if (Ext.isEmpty(url)) {
		return;
	}
	var head = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.setAttribute('src',	url);
	script.setAttribute('type', 'text/javascript');
	head.appendChild(script);
}

/**
 * Include JS scripts in the given order and trigger callback when all scripts are loaded  
 * @param ConfUrls {Array} the list of scripts to load
 * @param indexAInclure {int} the index during the iteration
 * @param callback {function} the callback
 * @param scope {Object} the scope of the callback
 */
function includeJsForceOrder(ConfUrls, indexAInclure, callback, scope) {
    //Test if all inclusions are done for this list of urls
    if (indexAInclure < ConfUrls.length) {
        var url = ConfUrls[indexAInclure].url;
        
        var trouve = false;
        var targetEl = "script";
        var targetAttr = "src";
        var scripts = document.getElementsByTagName(targetEl);
        var script;
        for (var i = scripts.length; i > 0; i--) {
            script = scripts[i - 1];
            if (script && script.getAttribute(targetAttr) !== null && script.getAttribute(targetAttr).indexOf(url) != -1) {
                trouve = true;
            }
        }
        if (!trouve) {
            // if not : include the Js Script
            var DSLScript = document.createElement("script");
            DSLScript.type = "text/javascript";
            DSLScript.onload = includeJsForceOrder.createDelegate(this, [ ConfUrls, indexAInclure + 1, callback, scope ]);
            DSLScript.onreadystatechange = includeJsForceOrder.createDelegate(this, [ ConfUrls, indexAInclure + 1, callback, scope ]);
            DSLScript.onerror = includeJsForceOrder.createDelegate(this, [ ConfUrls, indexAInclure + 1, callback, scope ]);
            DSLScript.src = url;

            var headID = document.getElementsByTagName('head')[0];
           headID.appendChild(DSLScript);           
        } else {
            includeJsForceOrder(ConfUrls, indexAInclure + 1, callback, scope);
        }
    } else {
        if (!Ext.isEmpty(callback)) {
            if (Ext.isEmpty(scope)) {
                callback.call();
            } else {
                callback.call(scope);
            }
        }
    }
}

function includeCss(url) {
	var headID = document.getElementsByTagName("head")[0];
	var newCss = document.createElement('link');
	newCss.type = 'text/css';
	newCss.rel = 'stylesheet';
	newCss.href = url;
	newCss.media = 'screen';
	// pas possible de monitorer l'evenement onload sur une balise link
	headID.appendChild(newCss);
}


Ext.override(Ext.PagingToolbar, {
    initComponent : function () {
        var T = Ext.Toolbar;
        var pagingItems = [this.first = new T.Button({
            tooltip: this.firstText,
            overflowText: this.firstText,
            iconCls: 'x-tbar-page-first',
            disabled: true,
            handler: this.moveFirst,
            scope: this
        }), this.prev = new T.Button({
            tooltip: this.prevText,
            overflowText: this.prevText,
            iconCls: 'x-tbar-page-prev',
            disabled: true,
            handler: this.movePrevious,
            scope: this
        }), '-', this.beforePageText,
        this.inputItem = new Ext.form.NumberField({
            cls: 'x-tbar-page-number',
            allowDecimals: false,
            allowNegative: false,
            enableKeyEvents: true,
            selectOnFocus: true,
            submitValue: false,
            listeners: {
                scope: this,
                keydown: this.onPagingKeyDown,
                blur: this.onPagingBlur
            }
        }), this.afterTextItem = new T.TextItem({
            text: String.format(this.afterPageText, 1)
        }), '-', this.next = new T.Button({
            tooltip: this.nextText,
            overflowText: this.nextText,
            iconCls: 'x-tbar-page-next',
            disabled: true,
            handler: this.moveNext,
            scope: this
        }), this.last = new T.Button({
            tooltip: this.lastText,
            overflowText: this.lastText,
            iconCls: 'x-tbar-page-last',
            disabled: true,
            handler: this.moveLast,
            scope: this
        }), '-'];


        var userItems = this.items || this.buttons || [];
        if (this.prependButtons) {
            this.items = userItems.concat(pagingItems);
        } else {
            this.items = pagingItems.concat(userItems);
        }
        delete this.buttons;
        if (this.displayInfo) {
            this.items.push('->');
            this.items.push(this.displayItem = new T.TextItem({}));
        }
        Ext.PagingToolbar.superclass.initComponent.call(this);
        this.addEvents(
            /**
             * @event change
             * Fires after the active page has been changed.
             * @param {Ext.PagingToolbar} this
             * @param {Object} pageData An object that has these properties:<ul>
             * <li><code>total</code> : Number <div class="sub-desc">The total number of records in the dataset as
             * returned by the server</div></li>
             * <li><code>activePage</code> : Number <div class="sub-desc">The current page number</div></li>
             * <li><code>pages</code> : Number <div class="sub-desc">The total number of pages (calculated from
             * the total number of records in the dataset as returned by the server and the current {@link #pageSize})</div></li>
             * </ul>
             */
            'change',
            /**
             * @event beforechange
             * Fires just before the active page is changed.
             * Return false to prevent the active page from being changed.
             * @param {Ext.PagingToolbar} this
             * @param {Object} params An object hash of the parameters which the PagingToolbar will send when
             * loading the required page. This will contain:<ul>
             * <li><code>start</code> : Number <div class="sub-desc">The starting row number for the next page of records to
             * be retrieved from the server</div></li>
             * <li><code>limit</code> : Number <div class="sub-desc">The number of records to be retrieved from the server</div></li>
             * </ul>
             * <p>(note: the names of the <b>start</b> and <b>limit</b> properties are determined
             * by the store's {@link Ext.data.Store#paramNames paramNames} property.)</p>
             * <p>Parameters may be added as required in the event handler.</p>
             */
            'beforechange'
        );
        this.on('afterlayout', this.onFirstLayout, this, {single: true});
        this.cursor = 0;
        this.bindStore(this.store, true);
    }, 
    onFirstLayout : function () {
        this.refresh = new Ext.Toolbar.Button({
            tooltip: i18n.get('label.refreshText'),
            overflowText: i18n.get('label.refreshText'),
            iconCls: 'x-tbar-loading',
            handler: this.doRefresh,
            scope: this
        });
        this.insert(10, this.refresh);
        if (this.dsLoaded) {
            this.onLoad.apply(this, this.dsLoaded);
        }
    }
});






/**
 * Build a {Ext.grid.ColumnModel} columnModel with a dataset informations
 * @param {Array} listeColonnes Array of dataset Columns
 * @param {Array} dictionnaryMappings Array of Dataset dictionnary mappings 
 * @param {Object} dataviewConfig the specific dataview Configuration.
 * @return {Ext.grid.ColumnModel} the builded columnModel
 */
function getColumnModel(listeColonnes, dictionnaryMappings, dataviewConfig, dataviewId) {
    var columns = [];
    if (!Ext.isEmpty(listeColonnes)) {
        Ext.each(listeColonnes, function (item, index, totalItems) {
            
            var tooltip = "";
            if (item.toolTip) {
                tooltip = item.toolTip;
            } else {
                if (Ext.isArray(dictionnaryMappings) && !Ext.isEmpty(dictionnaryMappings)) {
                    var dico = dictionnaryMappings[0];
                    var dicoMapping = dico.mapping || [];
                    dicoMapping.each(function (mapping) {
                        if (item.columnAlias == mapping.columnAlias) {
                            var concept = mapping.concept || {};
                            if (!Ext.isEmpty(concept.description)) {
                                tooltip += concept.description.replace('"', "''") + "<br>";
                            }
                        }
                    });
                }
            }
           
            var renderer = sitools.user.component.dataviews.dataviewUtils.getRendererLiveGrid(item, dataviewConfig, dataviewId);
            var hidden;
            if (Ext.isEmpty(item.visible)) {
                hidden = item.hidden;
            } else {
                hidden = !item.visible;
            }
            if (Ext.isEmpty(item.columnRenderer) ||  ColumnRendererEnum.NO_CLIENT_ACCESS != item.columnRenderer.behavior) {
	            columns.push(new Ext.grid.Column({
	                columnAlias : item.columnAlias,
	                dataIndexSitools : item.dataIndex,
	                dataIndex : item.columnAlias,
	                header : item.header,
	                width : item.width,
	                sortable : item.sortable,
	                hidden : hidden,
	                tooltip : tooltip,
	                renderer : renderer,
	                schema : item.schema,
	                tableName : item.tableName,
	                tableAlias : item.tableAlias,
	                id : item.id,
	                // urlColumn : item.urlColumn,
	                primaryKey : item.primaryKey,
	                previewColumn : item.previewColumn,
	                filter : item.filter,
	                sqlColumnType : item.sqlColumnType, 
//	                columnAliasDetail : item.columnAliasDetail,
					columnRenderer : item.columnRenderer, 
//					datasetDetailId : item.datasetDetailId, 
					specificColumnType : item.specificColumnType,
//	                image : item.image,
//	                datasetDetailUrl : item.datasetDetailUrl,
					menuDisabled : true,
	                format : item.format
	            }));
            }
            
        }, this);
    }

    var cm = new Ext.grid.ColumnModel({
        columns : columns
    });
    return cm;
}


//Date.formatFunctions['sitoolsGrid Y-m-d H:i:s'] = function () {
//	if (this.getHours() === 0 && this.getMinutes() === 0 && this.getSeconds() === 0) {
//		return this.format(BDD_DATE_FORMAT);
//	}
//	else {
//		return this.format(BDD_DATE_FORMAT_WITH_TIME);
//	}
//};


Ext.override(Ext.menu.DateMenu, {
    initComponent : function () {
        this.on('beforeshow', this.onBeforeShow, this);
        if (this.strict == (Ext.isIE7 && Ext.isStrict)) {
            this.on('show', this.onShow, this, {single: true, delay: 20});
        }
        Ext.apply(this, {
            plain: true,
            showSeparator: false,
            items: this.picker = new Ext.SitoolsDatePicker(Ext.applyIf({
                internalRender: this.strict || !Ext.isIE,
                ctCls: 'x-menu-date-item',
                id: this.pickerId
            }, this.initialConfig))
        });
        this.picker.purgeListeners();
        Ext.menu.DateMenu.superclass.initComponent.call(this);
        
        this.relayEvents(this.picker, ['select']);
        this.on('show', this.picker.focus, this.picker);
        this.on('select', this.menuHide, this);
        if (this.handler) {
            this.on('select', this.handler, this.scope || this);
        }
    }
});

Ext.override(Ext.form.DateField,  {
    
    showTime : false,
    
    onTriggerClick : function () {
        if (this.disabled) {
            return;
        }
        if (Ext.isEmpty(this.menu)) {
            this.menu = new Ext.menu.DateMenu({
                hideOnClick: false,
                showTime : this.showTime, 
                focusOnSelect: false
            });
        }
        this.onFocus();
        Ext.apply(this.menu.picker,  {
            minDate : this.minValue,
            maxDate : this.maxValue,
            disabledDatesRE : this.disabledDatesRE,
            disabledDatesText : this.disabledDatesText,
            disabledDays : this.disabledDays,
            disabledDaysText : this.disabledDaysText,
            format : this.format,
            showToday : this.showToday,
            minText : String.format(this.minText, this.formatDate(this.minValue)),
            maxText : String.format(this.maxText, this.formatDate(this.maxValue))
        });
        this.menu.picker.setValue(this.getValue() || new Date());
        this.menu.show(this.el, "tl-bl?");
        this.menuEvents('on');
    }
    
    
    
});
/**
 * Display the content of the file located at the given Url depending on its
 * content type
 * 
 * @param url
 *            the url of the file
 * @param title
 *            the title of the window to open
 */
function viewFileContent(url, title) {
  // build first request to get the headers
    Ext.Ajax.request({
        url : url,
        method : 'HEAD',
        scope : this,
        success : function (ret) {            
            try {
                var headerFile = ret.getResponseHeader("Content-Type").split(";")[0].split("/")[0];
                if (headerFile == "text" || ret.getResponseHeader("Content-Type").indexOf("application/json") >= 0) {
                    Ext.Ajax.request({
                        url : url,
                        method : 'GET',
                        scope : this,
                        success : function (ret) {
                            var windowConfig = {
                                id : "winPreferenceDetailId", 
                                title : title, 
                                iconCls : "version"
                            };
                            var jsObj = sitools.user.component.entete.userProfile.viewTextPanel;
                            var componentCfg = {
                                url : url,
                                text : ret.responseText,
                                formatJson : (ret.getResponseHeader("Content-Type").indexOf("application/json") >= 0)
						    };
                            SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, jsObj);
                        }
                    });
                }
                else if (headerFile == "image") {
                    sitools.user.component.dataviews.dataviewUtils.showPreview(url, title);

                }
                else {
                    sitools.user.component.dataviews.dataviewUtils.downloadFile(url);
                }
            } catch (err) {
                Ext.Msg.alert(i18n.get('label.error'), err);
            }
        },
        failure : function (ret) {
            return null;
        }
    });
}

Ext.override(Ext.data.XmlReader, {
    buildExtractors : function () {
        if (this.ef) {
            return;
        }
        var s       = this.meta,
            Record  = this.recordType,
            f       = Record.prototype.fields,
            fi      = f.items,
            fl      = f.length;

        if (s.totalProperty) {
            this.getTotal = this.createAccessor(s.totalProperty);
        }
        if (s.successProperty) {
            this.getSuccess = this.createAccessor(s.successProperty);
        }
        if (s.messageProperty) {
            this.getMessage = this.createAccessor(s.messageProperty);
        }
        this.getRoot = function (res) {
            return (!Ext.isEmpty(res[this.meta.record])) ? res[this.meta.record] : res[this.meta.root];
        };
        if (s.idPath || s.idProperty) {
            var g = this.createAccessor(s.idPath || s.idProperty);
            this.getId = function (rec) {
                var id = g(rec) || rec.id;
                return (id === undefined || id === '') ? null : id;
            };
        } else {
            this.getId = function () {
                return null;
            };
        }
        var ef = [];
        for (var i = 0; i < fl; i++) {
            f = fi[i];
            var map = (f.mapping !== undefined && f.mapping !== null) ? f.mapping : f.name;
            if (f.createAccessor !== undefined && f.createAccessor !== null) {
				ef.push(f.createAccessor);
			}
			else {
				ef.push(this.createAccessor(map));
			}
        }
        this.ef = ef;
    }
});

Ext.override(Ext.layout.BorderLayout.Region, {
    getCollapsedEl : function () {
        if (!this.collapsedEl) {
            if (!this.toolTemplate) {
                var tt = new Ext.Template(
                     '<span class="x-panel-collapsed-text">{title}</span>', 
					 '<div class="x-tool x-tool-{id}">&#160;</div>'
                );
				
                tt.disableFormats = true;
                tt.compile();
                Ext.layout.BorderLayout.Region.prototype.toolTemplate = tt;
            }
            this.collapsedEl = this.targetEl.createChild({
                cls: "x-layout-collapsed x-layout-collapsed-" + this.position,
                id: this.panel.id + '-xcollapsed'
            });
			
            this.collapsedEl.enableDisplayMode('block');

            if (this.collapseMode == 'mini') {
                this.collapsedEl.addClass('x-layout-cmini-' + this.position);
                this.miniCollapsedEl = this.collapsedEl.createChild({
					cls : "x-layout-mini x-layout-mini-" + this.position, 
					html : "&#160;"
                });
                this.miniCollapsedEl.addClassOnOver('x-layout-mini-over');
                this.collapsedEl.addClassOnOver("x-layout-collapsed-over");
                this.collapsedEl.on('click', this.onExpandClick, this, {stopEvent : true});
            }
            else {
                if (this.collapsible !== false && !this.hideCollapseTool) {
                    var t = this.expandToolEl = this.toolTemplate.append(
                        this.collapsedEl.dom,
                        {
							id: 'expand-' + this.position, 
							title : this.panel.collapsedTitle
						}, true);
                    t.addClassOnOver('x-tool-expand-' + this.position + '-over');
                    t.on('click', this.onExpandClick, this, {
						stopEvent: true
                    });
                }
                if (this.floatable !== false || this.titleCollapse) {
					this.collapsedEl.addClassOnOver("x-layout-collapsed-over");
					this.collapsedEl.on("click", this[this.floatable ? 'collapseClick' : 'onExpandClick'], this);
                }
            }
        }
        return this.collapsedEl;
    }

});

Ext.ns("sitools.user");

/**
 * A méthod call when click on dataset Icon. Request the dataset, and open a window depending on type
 * 
 * @static
 * @param {string} url the url to request the dataset
 * @param {string} type the type of the component.
 * @param {} extraCmpConfig an extra config to apply to the component.
 */
sitools.user.clickDatasetIcone = function (url, type, extraCmpConfig) {
	Ext.Ajax.request({
		method : "GET", 
		url : url, 
		success : function (ret) {
            var Json = Ext.decode(ret.responseText);
            if (showResponse(ret)) {
                var dataset = Json.dataset;
	            var componentCfg, javascriptObject;
	            var windowConfig = {
	                datasetName : dataset.name, 
	                type : type, 
	                saveToolbar : true, 
	                toolbarItems : []
	            };
                switch (type) {
				case "desc" : 
					Ext.apply(windowConfig, {
						title : i18n.get('label.description') + " : " + dataset.name, 
						id : "desc" + dataset.id, 
						saveToolbar : false, 
						iconCls : "version"
					});
					
					componentCfg = {
						autoScroll : true,
						html : dataset.descriptionHTML
					};
					Ext.applyIf(componentCfg, extraCmpConfig);
					javascriptObject = Ext.Panel;
					SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);
					
					break;
				case "data" : 
                    javascriptObject = eval(SitoolsDesk.navProfile.getDatasetOpenMode(dataset));
                
	                Ext.apply(windowConfig, {
	                    winWidth : 900, 
	                    winHeight : 400,
                        title : i18n.get('label.dataTitle') + " : " + dataset.name, 
                        id : type + dataset.id, 
                        iconCls : "dataviews"
	                });
                    
	                componentCfg = {
	                    dataUrl : dataset.sitoolsAttachementForUsers,
	                    datasetId : dataset.Id,
	                    datasetCm : dataset.columnModel, 
	                    datasetName : dataset.name,
	                    dictionaryMappings : dataset.dictionaryMappings,
	                    datasetViewConfig : dataset.datasetViewConfig, 
	                    preferencesPath : "/" + dataset.datasetName, 
	                    preferencesFileName : "datasetOverview", 
	                    sitoolsAttachementForUsers : dataset.sitoolsAttachementForUsers
	                };
                
                
	                Ext.applyIf(componentCfg, extraCmpConfig);
					SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);

					break;
				case "forms" : 
		            var menuForms = new Ext.menu.Menu();
		            Ext.Ajax.request({
						method : "GET", 
						url : dataset.sitoolsAttachementForUsers + "/forms", 
						success : function (ret) {
							try {
								var Json = Ext.decode(ret.responseText);
								if (! Json.success) {
									throw Json.message;
								}
								if (Json.total === 0) {
									throw i18n.get('label.noForms');
								}
				                javascriptObject = sitools.user.component.forms.mainContainer;
								if (Json.total == 1) {
						            var form = Json.data[0];
						            Ext.apply(windowConfig, {
						                title : i18n.get('label.forms') + " : " + dataset.name + "." + form.name, 
						                iconCls : "forms"
						            });
						            
						
					                Ext.apply(windowConfig, {
					                    id : type + dataset.id + form.id
					                });
					                componentCfg = {
					                    dataUrl : dataset.sitoolsAttachementForUsers,
					                    dataset : dataset, 
					                    formId : form.id,
					                    formName : form.name,
					                    formParameters : form.parameters,
					                    formZones : form.zones,
					                    formWidth : form.width,
					                    formHeight : form.height, 
					                    formCss : form.css, 
				                        preferencesPath : "/" + dataset.name + "/forms", 
				                        preferencesFileName : form.name
					                };
					                Ext.applyIf(componentCfg, extraCmpConfig);
									SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);

				                }
								else {
									
									var handler = null;
									Ext.each(Json.data, function (form) {
										handler = function (form, dataset) {
											Ext.apply(windowConfig, {
												title : i18n.get('label.forms') + " : " + dataset.name + "." + form.name, 
												iconCls : "forms"
								            });
								
							                Ext.apply(windowConfig, {
							                    id : type + dataset.id + form.id
							                });
							                componentCfg = {
							                    dataUrl : dataset.sitoolsAttachementForUsers,
							                    formId : form.id,
							                    formName : form.name,
							                    formParameters : form.parameters,
							                    formWidth : form.width,
							                    formHeight : form.height, 
							                    formCss : form.css, 
							                    dataset : dataset
							                };
							                Ext.applyIf(componentCfg, extraCmpConfig);
											SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);
										};
										menuForms.addItem({
											text : form.name, 
											handler : function () {
												handler(form, dataset);
											}, 
											icon : loadUrl.get('APP_URL') + "/common/res/images/icons/tree_forms.png"
										});
						                
									}, this);
									menuForms.showAt(Ext.EventObject.xy);
								}
					            
				
								
							}
							catch (err) {
								var tmp = new Ext.ux.Notification({
						            iconCls : 'x-icon-information',
						            title : i18n.get('label.information'),
						            html : i18n.get(err),
						            autoDestroy : true,
						            hideDelay : 1000
						        }).show(document);
							}
						}
		            });

					break;
				case "feeds" : 
		            var menuFeeds = new Ext.menu.Menu();
		            Ext.Ajax.request({
						method : "GET", 
						url : dataset.sitoolsAttachementForUsers + "/feeds", 
						success : function (ret) {
							try {
								var Json = Ext.decode(ret.responseText);
								if (! Json.success) {
									throw Json.message;
								}
								if (Json.total === 0) {
									throw i18n.get('label.noFeeds');
								}
				                javascriptObject = sitools.widget.FeedGridFlux;
								if (Json.total == 1) {
						            var feed = Json.data[0];
						            Ext.apply(windowConfig, {
						                title : i18n.get('label.feeds') + " : (" + dataset.name + ") " + feed.title, 
						                id : type + dataset.id + feed.id, 
						                iconCls : "feedsModule"
						            });
						
					                componentCfg = {
					                    datasetId : dataset.id,
					                    urlFeed : dataset.sitoolsAttachementForUsers + "/clientFeeds/" + feed.name,
					                    feedType : feed.feedType, 
					                    datasetName : dataset.name,
					                    feedSource : feed.feedSource,
					                    autoLoad : true
					                };
						            Ext.applyIf(componentCfg, extraCmpConfig);
									SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);

				                }
								else {
									var handler = null;
									Ext.each(Json.data, function (feed) {
										handler = function (feed, dataset) {
											Ext.apply(windowConfig, {
												title : i18n.get('label.feeds') + " : (" + dataset.name + ") " + feed.title, 
												id : type + dataset.id + feed.id, 
												iconCls : "feedsModule"
								            });
								
							                
							                componentCfg = {
							                    datasetId : dataset.id,
							                    urlFeed : dataset.sitoolsAttachementForUsers + "/clientFeeds/" + feed.name,
							                    feedType : feed.feedType, 
							                    datasetName : dataset.name,
							                    feedSource : feed.feedSource,
							                    autoLoad : true
							                };
							                Ext.applyIf(componentCfg, extraCmpConfig);
											SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);
										};
										menuFeeds.addItem({
											text : feed.name, 
											handler : function () {
												handler(feed, dataset);
											}, 
											icon : loadUrl.get('APP_URL') + "/common/res/images/icons/rss.png"
										});
						                
									}, this);
									menuFeeds.showAt(Ext.EventObject.xy);
								}
					            
				
								
							}
							catch (err) {
								var tmp = new Ext.ux.Notification({
						            iconCls : 'x-icon-information',
						            title : i18n.get('label.information'),
						            html : i18n.get(err),
						            autoDestroy : true,
						            hideDelay : 1000
						        }).show(document);
							}
						}
		            });

					break;
				case "defi" : 
		            Ext.apply(windowConfig, {
		                title : i18n.get('label.definitionTitle') + " : " + dataset.name, 
		                id : type + dataset.id, 
		                iconCls : "semantic"
		            });
		
	                javascriptObject = sitools.user.component.columnsDefinition;
	                
	                componentCfg = {
	                    datasetId : dataset.id,
	                    datasetCm : dataset.columnModel, 
	                    datasetName : dataset.name,
                        dictionaryMappings : dataset.dictionaryMappings, 
                        preferencesPath : "/" + dataset.name, 
                        preferencesFileName : "semantic"
	                };
	                Ext.applyIf(componentCfg, extraCmpConfig);
					SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);

					break;
				case "openSearch" : 
		            Ext.Ajax.request({
						method : "GET", 
						url : dataset.sitoolsAttachementForUsers + "/opensearch.xml", 
						success : function (ret) {
                            var xml = ret.responseXML;
                            var dq = Ext.DomQuery;
                            // check if there is a success node
                            // in the xml
                            var success = dq.selectNode('OpenSearchDescription ', xml);
							if (!success) {
								var tmp = new Ext.ux.Notification({
						            iconCls : 'x-icon-information',
						            title : i18n.get('label.information'),
						            html : i18n.get("label.noOpenSearch"),
						            autoDestroy : true,
						            hideDelay : 1000
						        }).show(document);
								return;
							}
							
							Ext.apply(windowConfig, {
				                title : i18n.get('label.opensearch') + " : " + dataset.name, 
				                id : type + dataset.id, 
				                iconCls : "openSearch"
				            });
				
			                javascriptObject = sitools.user.component.datasetOpensearch;
			                
			                componentCfg = {
			                    datasetId : dataset.id,
			                    dataUrl : dataset.sitoolsAttachementForUsers, 
			                    datasetName : dataset.name, 
		                        preferencesPath : "/" + dataset.name, 
		                        preferencesFileName : "openSearch"
			                };
			                Ext.applyIf(componentCfg, extraCmpConfig);
							SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, javascriptObject);
                            
                        }
		            });

					break;
				}
            }
		}, 
		failure : alertFailure
	});
};

/**
 * Add a tooltip on every form field: tooltip could be an object like tooltip : {
 * text : string width : number }, or a simple string
 */
Ext.override(Ext.form.Field, {
	tooltip : null, 
	listeners : {
		render: function () {
			Ext.form.Field.superclass.render.apply(this, arguments);
			
			if (!Ext.isEmpty(this.tooltip)) {
				var ttConfig = {};
				if (Ext.isString(this.tooltip)) {
					ttConfig = {
						html : this.tooltip, 
						width : 200, 
						dismissDelay : 5000
					};
				} 
				else if (Ext.isObject(this.tooltip)) {
                    ttConfig = this.tooltip;
                } else {
                    return;
                }
                Ext.apply(ttConfig, {
                    target : this.el
                });
				this.tTip = new Ext.ToolTip(ttConfig);
			}
		}
	}
});

/**
 * Add a tooltip on every boxcomponent : tooltip could be an object like tooltip : {
 * text : string width : number }, or a simple string
 */
Ext.override(Ext.BoxComponent, {
    tooltip : null, 
    listeners : {
        render: function () {
            Ext.BoxComponent.superclass.render.apply(this, arguments);
            
            if (!Ext.isEmpty(this.tooltip)) {
                var ttConfig = {};
                if (Ext.isString(this.tooltip)) {
                    ttConfig = {
                        html : this.tooltip, 
                        width : 200, 
                        dismissDelay : 5000
                    };
                } 
                else if (Ext.isObject(this.tooltip)) {
                    ttConfig = this.tooltip;
                } else {
                    return;
                }
                Ext.apply(ttConfig, {
                    target : this.el
                });
                this.tTip = new Ext.ToolTip(ttConfig);
            }
        }
    }
});

/**
 * Add a tooltip on every boxcomponent : tooltip could be an object like tooltip : {
 * text : string width : number }, or a simple string
 */
Ext.override(Ext.Button, {
    setTooltip : function() {
		return;
	}
});

/**
 * Get the folder name to store the cart file name depending on the project name
 * @param projectName the project name
 * @returns {String} the folder name to store the cart file
 */
function getCartFolder (projectName) {
    return "/" + DEFAULT_ORDER_FOLDER + "/cart/" + projectName;
}

Ext.override(Ext.Window, {
    /**
     * Fit a window to its container (desktop)
     * Resizing and repositionning
     */
    fitToDesktop : function () {
        //resize windows to fit desktop
        var vs = this.container.getViewSize(false);
        var winSize = this.getSize();
        var winPos = this.getPosition()
        
        var outputWinSize = winSize;
        var outputWinPos = winPos;
        
        
        if(winSize.width > vs.width) {
            outputWinSize.width = vs.width - 5;
        }

        if(winSize.height > vs.height) {
            outputWinSize.height = vs.height - 5;
        }
        this.setSize(outputWinSize.width, outputWinSize.height);
        
        
        if(winPos[0] + outputWinSize.width > vs.width) {
            outputWinPos.x = 0;
        }

        if(winPos[1] + outputWinSize.height > vs.height) {
            outputWinPos.y = 0;
        }
        this.setPosition(outputWinPos.x, outputWinPos.y);
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*!
 * Ext JS Library 3.2.1
 * Copyright(c) 2006-2010 Ext JS, Inc.
 * licensing@extjs.com
 * http://www.extjs.com/license
 */

/*global Ext, i18n, locale:true, sitools, loadUrl, userLogin, DEFAULT_PREFERENCES_FOLDER*/
/*
 * @include "../../client-public/js/siteMap.js"
 * @include "portal/portal.js"
 */

// Sample desktop configuration
function initAppliDesktop() {
    return;
}

var portal;

var portalApp = {
    projects : null,
    languages : null,
    preferences : null,
	//callbacks : [this.callSiteMapResource, this.initProjects, this.initLanguages, this.initPreferences]
    autoChainAjaxRequest : true,
    initProjects : function (callback) {
        Ext.Ajax.request({
            scope : this,
            /* sitools/portal/projects...*/
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_PORTAL_URL') + '/projects?media=json', 
//            url : '/sitools/portal/projects?media=json', 
            method : 'GET',
            success : function (response) {
                try {
                    this.projects = Ext.decode(response.responseText).data;
                    if (this.autoChainAjaxRequest) {
						this.initLanguages();
                    }
                } catch (err) {
                    Ext.Msg.alert(i18n.get('label.error'), err);
                }

                // portal = new sitools.Portal(response.responseJSON.data);
            },
            failure : function (response) {
                Ext.Msg.alert('Status', i18n.get('warning.serverError'));
            }
        });
    },
    initLanguages : function () {
        Ext.Ajax.request({
            scope : this,
            method : "GET",
            /* /sitools/client-user */
//            url : loadUrl.get('APP_URL') + loadUrl.get('APP_CLIENT_USER_URL') + '/tmp/langues.json',
            url : loadUrl.get('APP_URL') + '/client-user/tmp/langues.json',
            success : function (response) {
                this.languages = Ext.decode(response.responseText).data;
                if (this.autoChainAjaxRequest) {
					this.initPreferences();
                }
            },
            failure : function (response) {
                Ext.Msg.alert('Status', i18n.get('warfning.serverError'));
            }
        });
    },
    initPreferences : function (cb) {
        if (Ext.isEmpty(userLogin)) {
            var projects = this.projects;
            var languages = this.languages;
            var preferences = this.preferences;
            var callback;
            if (this.autoChainAjaxRequest) {
				callback = function () {
	                // loadUrl.load('/sitools/client-user/siteMap', function (){
	                portal = new sitools.Portal(projects, languages, preferences);
	                // });
	            };
            }
            else {
				callback = cb;
            }
            i18n.load(loadUrl.get('APP_URL') + '/res/i18n/' + locale.getLocale() + '/gui.properties', callback);
            return;
        }
        var filePath = "/" + DEFAULT_PREFERENCES_FOLDER + '/portal';
        var success = function (response) {
            this.preferences = Ext.decode(response.responseText);
            if (!Ext.isEmpty(this.preferences.language)) {
                locale.setLocale(this.preferences.language);
            }

        };
        var failure = function () {
        	return;
        };
        var callback = function () {
            var projects = this.projects;
            var languages = this.languages;
            var preferences = this.preferences;
            i18n.load(loadUrl.get('APP_URL') + '/res/i18n/' + locale.getLocale() + '/gui.properties', function () {
                // loadUrl.load('/sitools/client-user/siteMap', function (){
                portal = new sitools.Portal(projects, languages, preferences);
                // });
            });
        };
        
        userStorage.get("portal", filePath, this, success, failure, callback);
        
    },
    initAppliPortal : function (opts, callback) {
        if (!Ext.isEmpty(Ext.util.Cookies.get('userLogin'))) {
            var auth = Ext.util.Cookies.get('hashCode');
            Ext.Ajax.defaultHeaders = {
                "Authorization" : auth,
                "Accept" : "application/json",
                "X-User-Agent" : "Sitools"
            };
        } else {
            Ext.Ajax.defaultHeaders = {
                "Accept" : "application/json",
                "X-User-Agent" : "Sitools"
            };
        }
        Ext.QuickTips.init();
//        this.callbacks[0](opts.siteMapRes, callback);
        this.callSiteMapResource(opts.siteMapRes, callback);
        //this.initProjects();
    },
    
    callSiteMapResource : function (res, cb) {
        var callback;
        if (this.autoChainAjaxRequest) {
			callback = this.initProjects;
        } else {
			callback = cb;
        } 
        loadUrl.load(res + '/siteMap', callback, this);
    }
};
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
var ID = {
    PANEL : {
        MENU : 'menuPanelId',
        TREE : 'treePanelId',
        MAIN : 'mainPanelId',
        HELP : 'helpPanelId'
    },
    CMP : {
        TOOLBAR : 'toolbarId',
        MENU : 'menuId'
    },
    WIN : {
        LOGIN : 'loginWinId',
        ORDER : 'orderWinId'
    },
    BOX : {
        REG : 'regBoxId',
        USER : 'userBoxId',
        GROUP : 'groupBoxId',
        FIREWALL : 'firewallBoxId'
    },
    PORTLET : {
        PROJET : 'portletProjectId',
        RECHERCHE : 'portletRecherceID',
        FEEDS : 'portletFeedsId'
    },
    PORTALTREENAV : {
        PROJET : 'navProjectId',
        RECHERCHE : 'navRechercheId',
        FEEDS : 'navFeedsId'

    }
};
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n, locale, utils_logout, window, userPreferences:true, userStorage, DEFAULT_PREFERENCES_FOLDER, ID, portal, userLogin, loadUrl, showVersion*/

sitools.Portal = function (projectsList, languages, preferences) {
    /***************************************************************************
     * Creation de la barre d'outil
     */
    var user;
    var menuLoginLogout;
    if (Ext.isEmpty(Ext.util.Cookies.get('userLogin'))) {
        user = i18n.get('label.guest');
        menuLoginLogout = {
            xtype : 'tbbutton',
            text : i18n.get('label.connection'),
            itemId : 'menu_login',
            icon : loadUrl.get('APP_URL') + '/common/res/images/icons/login.png',
            scope : this,
            handler : function () {
                sitools.userProfile.LoginUtils.connect({
                    closable : true,
                    url : loadUrl.get('APP_URL') + '/login',
                    register : loadUrl.get('APP_URL') + '/inscriptions/user',
                    reset : loadUrl.get('APP_URL') + '/resetPassword',
                    handler : function () {
                        portal.initAppliPortal({
                            siteMapRes : loadUrl.get('APP_URL') + loadUrl.get('APP_CLIENT_USER_URL')
                        });
                    }
                });
                
                
            }

        };
    } else {
        user = Ext.util.Cookies.get('userLogin');
        menuLoginLogout = {
            xtype : 'tbbutton',
            text : i18n.get('label.logout'),
            itemId : 'menu_logout',
            icon : loadUrl.get('APP_URL') + '/common/res/images/icons/logout.png',
            scope : this,
            handler : sitools.userProfile.LoginUtils.logout
        };

    }
    var versionButton = {
            xtype : 'tbbutton',
            text : i18n.get('label.version'),
            itemId : 'menu_version',
            icon : loadUrl.get('APP_URL') + '/common/res/images/icons/version.png',
            handler : function () {
                showVersion();
            }

        };
    var menuLangues = new Ext.menu.Menu({
        plain : true
    });
    Ext.each(languages, function (language) {
        menuLangues.add({
            text : language.displayName,
            scope : this,
            handler : function () {
                var callback = function () {
                    Ext.util.Cookies.set('language', language.localName);
                    window.location.reload();
                };
                var date = new Date();
                Ext.util.Cookies.set('language', language.localName, date.add(Date.MINUTE, 20));
                userPreferences = {};
                userPreferences.language = language.localName;
                if (!Ext.isEmpty(userLogin)) {
                    userStorage.set(loadUrl.get('APP_PORTAL_URL'),  "/" + DEFAULT_PREFERENCES_FOLDER + loadUrl.get('APP_PORTAL_URL'), userPreferences, callback);
//                    userStorage.set("portal",  "/" + DEFAULT_PREFERENCES_FOLDER + "/portal", userPreferences, callback);
                } else {
                    window.location.reload();
                }

            },
            icon : language.image
        });
    }, this);
    
    var editProfileButton;
    if (!Ext.isEmpty(Ext.util.Cookies.get('userLogin'))) {
	    editProfileButton = {
	            xtype : 'tbbutton',
	            text : i18n.get('label.editProfile'),
	            itemId : 'menu_editProfile',
	            icon : loadUrl.get('APP_URL') + '/common/res/images/icons/tree_userman.png',
	            identifier : user,
	            edit : loadUrl.get('APP_URL') + '/editProfile/' + user,
	            scope : this,
	            handler : function (button, e) {	                
	                var callback = Ext.createDelegate(this.onEditProfile, this, [user, button.edit]);
	                sitools.userProfile.LoginUtils.editProfile(callback);
	            }
	    
	        };
    } else {
        editProfileButton = {
            xtype : 'tbbutton',
            hidden : true
        };
    }
    

    var toolbar = {
        xtype : 'toolbar',
        id : 'toolbar',
        items : [ {
            xtype : 'label',
            html : '<img src=' + loadUrl.get('APP_URL') + '/common/res/images/cnes.png width=92 height=28>'
        }, {
            xtype : 'label',
            html : '<img src=' + loadUrl.get('APP_URL') + '/common/res/images/logo_01_petiteTaille.png width=92 height=28>'
        }, '->', {
            xtype : 'label',
            margins : {
                top : 0,
                right : 10,
                bottom : 0,
                left : 10
            },
            text : i18n.get('label.welcome') + ' ' + user
        }, '-', versionButton, '-', {
            text : i18n.get('label.langues'),
            menu : menuLangues
        }, '-', editProfileButton, '-', menuLoginLogout
        
		/*
         * , {xtype : 'button', text :
         * i18n.get('label.connection'), handler :
         * this.connect}
         */
        ]
    };

    var menuPanel = new Ext.Panel({
        id : 'north',
        region : 'north',
        layout : 'fit',
        height : 28,
        items : [ toolbar ]
    });

    /***************************************************************************
     * Creation du menu d'affichage des portlets
     */
    var treePanel = new Ext.Panel({
        id : 'tree',
        region : 'west',
        title : i18n.get('label.components'),
        split : true,
        collapsible : true,
        autoScroll : true,
        width : 200,
        layout : 'fit',
        defaults : {
            padding : 10
        },
        collapsed : true
    });

    /***************************************************************************
     * Creation du portlet Liste des projets
     */

    var data = [];
    var store = new Ext.data.JsonStore({
        fields : [ 'id', 'name', 'description', 'image', 'authorized', 'maintenance', 'maintenanceText' ],
        sortInfo : {
            field : 'name',
            direction : 'ASC'
        }
    });

    Ext.each(projectsList, function (project) {
		var record = new Ext.data.Record({
			id : project.id, 
			name : project.name, 
			description : project.description, 
			image : project.image.url || SITOOLS_DEFAULT_PROJECT_IMAGE_URL, 
			authorized : project.authorized, 
			maintenance : project.maintenance, 
			maintenanceText : project.maintenanceText
		});
       // var record = new Ext.data.Record([ project.id, project.name, project.description, project.image.url, project.authorized ]);
		store.add(record);
    });

    var myDataView = new Ext.DataView({
        store : store, 
        tpl : new Ext.XTemplate('<ul>', '<tpl for=".">', 
				'<li id="{id}" ', 
				'<tpl if="authorized == true">',
					'class="project',
					'<tpl if="maintenance">',
						' sitools-maintenance-portal',
					'</tpl>',
					'"', 
				'</tpl>', 
				'<tpl if="authorized == false">',
					'class="project projectUnauthorized"',
				'</tpl>', 
				'>', 
				'<img width="80" height="80" src="{image}" />', '<strong>{name}</strong>',
                '<span>{description} </span>', '</li>', '</tpl>', '</ul>', 
                {
				compiled : true, 
				disableFormats : true, 
				isAuthorized : function (authorized) {
					return authorized === true;
				}
            }),

        // plugins : [
        // new Ext.ux.DataViewTransition({
        // duration : 550,
        // idProperty: 'id'
        // })
        // ],
        id : 'projectDataView',
        itemSelector : 'li.project',
        overClass : 'project-hover',
        singleSelect : true,
        multiSelect : false,
        autoScroll : true,
        listeners : {
            scope : this,
            click : function (dataView, index, node, e) {
                // get the projectId
                
                var data = dataView.getRecord(node).data;
                var projectName = data.name;
                var authorized = data.authorized;
				var maintenance = data.maintenance;
				var maintenanceText = data.maintenanceText;
                if (authorized) {
					if (!maintenance) {
						window.open(projectName + "/project-index.html");
					}
					else {
						var alertWindow = new Ext.Window({
							title : i18n.get('label.maintenance'),
							width : 600, 
							height : 400, 
							autoScroll : true, 
							items : [{
								xtype : 'panel', 
								layout : 'fit', 
								autoScroll : true, 
								html : maintenanceText, 
								padding : "5"
							}], 
							modal : true
						});
						alertWindow.show();
					}
                } else {
                	sitools.userProfile.LoginUtils.connect({
                        closable : true,
                        url : loadUrl.get('APP_URL') + '/login',
                        register : loadUrl.get('APP_URL') + '/inscriptions/user',
                        reset : loadUrl.get('APP_URL') + '/resetPassword',
                        handler : function () {
                        	if (!maintenance) {
                        		window.open(projectName + "/project-index.html");
                        	}
                        }
                    });
					//Ext.Msg.alert(i18n.get('label.warning'), i18n.get('label.unauthorized'));
                }
                // create the new url with the given projectId
                
            }
        }
    });

    var portletProjet = new Ext.ux.Portlet({
        id : ID.PORTLET.PROJET,
        title : i18n.get('label.portletProjetTitle'),
        height : 560,
        // tbar : tbar,
        items : [ myDataView ],
        autoScroll : true
    });

        /***************************************************************************
     * Creation du portlet d'affichage des flux de l'archive
     */

    var panelFluxPortal = {
        xtype : 'sitools.component.users.portal.feedsReaderPortal'
    };

    // panelFlux.loadFeed( '/sitools/client-user/tmp/feed-proxy.xml');

    var portletFluxPortal = new Ext.ux.Portlet({
        layout : 'fit',
        id : ID.PORTLET.FEEDS,
        title : i18n.get('title.portlelFeedsPortal'),
        height : 400,
        items : [ panelFluxPortal ]
    });

    /***************************************************************************
     * Creation du portlet Open Search
     */
    
    var osPanel = new sitools.component.users.portal.portalOpensearch({
        dataUrl : loadUrl.get('APP_URL') + loadUrl.get('APP_PORTAL_URL'),
        suggest : false,
        pagging : false
        
    });
   
    var portletRecherche = new Ext.ux.Portlet({
        collapsed : true, 
        bodyCssClass : 'portletRecherche',
        id : ID.PORTLET.RECHERCHE,
        title : i18n.get('label.portletRechercheTitle'),        
        items : [ osPanel ],
        layout: "fit", 
        height : 400
    });

    /***************************************************************************
     * Creation des autres composants du tabPanel
     */

    var helpPanel = new Ext.ux.ManagedIFrame.Panel({
        id : 'helpPanelId',
        title : i18n.get('label.helpTitle'),
        // split: true,
        // collapsible: true,
        autoScroll : true,
        // layout: 'fit',
        defaults : {
            padding : 10
        },
        defaultSrc : "res/html/" + locale.getLocale() + "/help.html"
    });

    var linkPanel = new Ext.ux.ManagedIFrame.Panel({
        id : 'link',
        title : i18n.get('label.linkTitle'),
        // split: true,
        // collapsible: true,
        autoScroll : true,
        // layout: 'fit',
        defaults : {
            padding : 10
        },
        defaultSrc : "res/html/" + locale.getLocale() + "/link.html"
    });

    var contactPanel = new Ext.ux.ManagedIFrame.Panel({
        id : 'help',
        title : i18n.get('label.contactTitle'),
        // split: true,
        // collapsible: true,
        autoScroll : true,
        // layout: 'fit',
        defaults : {
            padding : 10
        },
        defaultSrc : "res/html/" + locale.getLocale() + "/contact.html"
    });

    /***************************************************************************
     * Creation tabPanel Center qui contient le portal
     */

    var mainPanel = new Ext.TabPanel({
        baseCls : 'portalMainPanel',
        region : 'center',
        activeTab : 0,
        // title: i18n.get('label.portalTitle'),
        // layout:'fit',
        items : [ {
            xtype : 'panel',
            baseCls : 'portalMainPanel',
            autoScroll : true,
            title : i18n.get('label.portalTitle'),
            items : [ {
                region : 'north',
                xtype : 'iframepanel',
                title : i18n.get('label.freeText'),
                autoScroll : true,
                defaults : {
                    padding : 10
                },
                defaultSrc : "res/html/" + locale.getLocale() + "/freeText.html",
                height : 200
            }, {
                region : 'center',
                baseCls : 'portalMainPanel',
                xtype : 'portal',
                id : 'portalId',
                // region:'center',
                margins : '35 5 5 0',
                // layout : 'fit',
                defaults : {
                    style : 'padding:10px 0 10px 10px'
                },
                items : [ {
                    columnWidth : 0.50,
                    style : 'padding:10px 0 10px 10px',
                    // baseCls : 'portalMainPanel',
                    items : [ portletProjet ]
                }, {
                    columnWidth : 0.50,
                    style : 'padding:10px',
                    // baseCls : 'portalMainPanel',
                    items : [ portletFluxPortal, portletRecherche]
                } ]
            } ]
        }

        , contactPanel, linkPanel, helpPanel ]

    /*
     * Uncomment this block to test handling of the drop event. You could use
     * this to save portlet position state for example. The event arg e is the
     * custom event defined in Ext.ux.Portal.DropZone.
     */
    });

    /***************************************************************************
     * Creation du viewport
     */
    sitools.Portal.superclass.constructor.call(this, Ext.apply({
        layout : 'border',
        items : [ menuPanel, treePanel, mainPanel ]
    }));

    var treeNav = new Ext.tree.TreePanel({
        id : 'panelNav',
        useArrows : true,
        autoScroll : true,
        animate : true,
        enableDD : false,
        containerScroll : true,
        rootVisible : false,
        width : 200,
        root : new Ext.tree.AsyncTreeNode({
            expanded : true,
            children : [ {
                id : ID.PORTALTREENAV.PROJET,
                panelId : ID.PORTLET.PROJET,
                icon : 'res/images/icons/portlet.png',
                text : i18n.get('label.portletProjetTitle'),
                leaf : true,
                checked : true,
                listeners : {
                    checkchange : function (node) {
                        if (!node.attributes.checked) {
                            Ext.get(node.attributes.panelId).hide();
                            // Pour que le panel n'ait plus de place reservee
                            // dans le portal
                            Ext.get(node.attributes.panelId).addClass('x-hide-display');
                        } else {
                            Ext.get(node.attributes.panelId).show();
                            Ext.get(node.attributes.panelId).removeClass('x-hide-display');
                        }
                    }
                }
            }, {
                id : ID.PORTALTREENAV.RECHERCHE,
                icon : 'res/images/icons/portlet.png',
                panelId : ID.PORTLET.RECHERCHE,
                text : i18n.get('label.portletRechercheTitle'),
                leaf : true,
                checked : true,
                listeners : {
                    checkchange : function (node) {
                        if (!node.attributes.checked) {
                            Ext.get(node.attributes.panelId).hide();
                            // Pour que le panel n'ait plus de place reservee
                            // dans le portal
                            Ext.get(node.attributes.panelId).addClass('x-hide-display');
                        } else {
                            Ext.get(node.attributes.panelId).show();
                            Ext.get(node.attributes.panelId).removeClass('x-hide-display');
                        }
                    }
                }
            }, {
                id : ID.PORTALTREENAV.FEEDS,
                icon : 'res/images/icons/portlet.png',
                panelId : ID.PORTLET.FEEDS,
                text : i18n.get('label.portletFeedsTitle'),
                leaf : true,
                checked : true,
                listeners : {
                    checkchange : function (node) {
                        if (!node.attributes.checked) {
                            Ext.get(node.attributes.panelId).hide();
                            // Pour que le panel n'ait plus de place reservee
                            // dans le portal
                            Ext.get(node.attributes.panelId).addClass('x-hide-display');
                        } else {
                            Ext.get(node.attributes.panelId).show();
                            Ext.get(node.attributes.panelId).removeClass('x-hide-display');
                        }
                    }
                }
            } ]
        }),
        listeners : {
            'checkchange' : function (node, checked) {
                if (checked) {
                    node.getUI().addClass('complete');
                } else {
                    node.getUI().removeClass('complete');
                }
            }
        }
    });
    treePanel.add(treeNav);
    treePanel.doLayout();
    // portletFlux.doLayout();

};

Ext.extend(sitools.Portal, Ext.Viewport, {
    onRender : function () {
        sitools.Portal.superclass.onRender.apply(this, arguments);
        // this.
        // this.doLayout();
    }, 
    
    onEditProfile : function (user, url) {
        var win = new Ext.Window({
            items : [], 
            modal : true, 
            width : 400, 
            height : 405, 
            resizable : false
        });
        
        win.show();
        var edit = new sitools.userProfile.editProfile({
            closable : true,
            identifier : user,
            url : url,
            height : win.body.getHeight()
        });
        win.add(edit);
        win.doLayout();
    }
});

Ext.reg('sitools.Portal', sitools.Portal);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, i18n, sitools, window, loadUrl */

Ext.namespace('sitools.component.users.portal');

sitools.component.users.portal.feedsReaderPortal = Ext.extend(Ext.Panel, {
    portalId : "idPortal",
    layout : "fit",
    initComponent : function () {
        var storeFeeds = new Ext.data.JsonStore({
            fields : [ 'id', 'name', 'feedType', 'title', 'feedSource', {
                name : 'visible',
                type : 'boolean'
            } ],
            url : loadUrl.get('APP_URL') + loadUrl.get('APP_PORTAL_URL') + '/' + this.portalId + '/listFeeds',
            root : "data",
            autoLoad : true,
            listeners : {
                scope : this, 
                load : function (store, records, options) {
                    if (store.getCount() !== 0) {
						this.comboFeeds.setValue(storeFeeds.getAt(0).data.id);
						this.selectFeeds(this.comboFeeds, storeFeeds.getAt(0));
			        }
                }
            }
        });

        this.comboFeeds = new Ext.form.ComboBox({
            // all of your config options
            store : storeFeeds,
            displayField : 'name',
            valueField : 'id',
            typeAhead : true,
            mode : 'local',
            forceSelection : true,
            triggerAction : 'all',
            emptyText : i18n.get('label.selectAFeed'),
            selectOnFocus : true,
            scope : this,
            listeners : {
                scope : this,
                select : this.selectFeeds

            }
        });

        this.buttonDate = this.createSorterButton({
            text: i18n.get("label.feedDate"),
            sortData: {
                direction: 'ASC'
            }
        });
        
        this.tbar = {
            xtype : 'toolbar',
            defaults : {
                scope : this
            },
            items : [ this.comboFeeds, this.buttonDate ]
        };

        /**/

        sitools.component.users.portal.feedsReaderPortal.superclass.initComponent.call(this);

    },

    selectFeeds : function (combo, rec, index) {
        this.remove(this.feedsReader);
        var url = loadUrl.get('APP_URL') + loadUrl.get('APP_PORTAL_URL') + "/" + this.portalId + "/clientFeeds/" + rec.data.name;

        this.feedsReader = new sitools.widget.FeedGridFlux({
            urlFeed : url,
            feedType : rec.data.feedType,
            feedSource : rec.data.feedSource,
            autoLoad : true
            
            
        });
        this.add(this.feedsReader);
        this.doSort();
        this.doLayout();
    },
    
    /**
     * Tells the store to sort itself according to our sort data
     */
    doSort : function () {
        if (Ext.isFunction(this.feedsReader.items.items[0].sortByDate)) {
            this.feedsReader.items.items[0].sortByDate(this.buttonDate.sortData.direction);
        }
    },
    
    /**
     * Convenience function for creating Toolbar Buttons that are tied to sorters
     * @param {Object} config Optional config object
     * @return {Ext.Button} The new Button object
     */
    createSorterButton : function (config) {
        config = config || {};
              
        Ext.applyIf(config, {
            listeners: {
                scope : this,
                click: function (button, e) {
                    this.changeSortDirection(button, true);                    
                }
            },
            iconCls: 'sort-' + config.sortData.direction.toLowerCase(),
            reorderable: true
        });
        
        return new Ext.Button(config);
    },
    
    /**
     * Callback handler used when a sorter button is clicked or reordered
     * @param {Ext.Button} button The button that was clicked
     * @param {Boolean} changeDirection True to change direction (default). Set to false for reorder
     * operations as we wish to preserve ordering there
     */
    changeSortDirection : function (button, changeDirection) {
        var sortData = button.sortData,
            iconCls  = button.iconCls;
        
        if (sortData != undefined) {
            if (changeDirection !== false) {
                button.sortData.direction = button.sortData.direction.toggle("ASC", "DESC");
                button.setIconClass(iconCls.toggle("sort-asc", "sort-desc"));
            }
            this.doSort();
        }
    },
    
    /**
     * Returns an array of sortData from the sorter buttons
     * @return {Array} Ordered sort data from each of the sorter buttons
     */
    getSorters : function () {
        var sorters = [];
        
        Ext.each(this.getTopToolbar().findByType('button'), function (button) {
            if (!Ext.isEmpty(button.sortData)) {
                sorters.push(button.sortData);
            }
        }, this);
        
        return sorters;
    }

});

Ext.reg('sitools.component.users.portal.feedsReaderPortal', sitools.component.users.portal.feedsReaderPortal);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, i18n, sitools, formPanel, result*/
/*
 * @include "../../components/viewDataDetail/simpleViewDataDetails.js"
 */

Ext.namespace('sitools.component.users.portal');
/**
 * @cfg {string} dataUrl the uri of the opensearch
 * @cfg {boolean} suggest true to activate autosuggest, false otherwise
 * @cfg {boolean} pagging true to activate the pagging, false otherwise
 * @class sitools.component.users.portal.portalOpensearch
 * @requires sitools.user.component.simpleViewDataDetail
 * @extends Ext.Panel
 * @requires sitools.user.component.openSearchResultFeed
 */
sitools.component.users.portal.portalOpensearch = function (config) {

    // set the uri for the opensearch engine
    // exemple de requete avec pagination
    // http://localhost:8182/sitools/solr/db?q=fu*&start=10&rows=20
    var uri = config.dataUrl + "/opensearch/search";
    var uriSuggest = config.dataUrl + "/opensearch/suggest";
    var suggest = true;
    if (!Ext.isEmpty(config.suggest)) {
        suggest = config.suggest;
    }

    var pagging = true;
    if (!Ext.isEmpty(config.pagging)) {
        pagging = config.pagging;
    }

    /**
     * click handler for the search button gets the search query and update the
     * RSS feed URI to display the results
     */
    function _clickOnSearch() {
        // create the opensearch url
        var searchQuery = formPanel.getForm().getValues().searchQuery;
        var nbResults = formPanel.getForm().getValues().nbResults;
        result.updateStore(uri + "?q=" + searchQuery + "&nbResults=" + nbResults);
    }

   /* var search = new Ext.form.TextField({
        fieldLabel : i18n.get("label.search"),
        name : 'searchQuery',
        anchor : "100%",
        listeners : {
            scope : this,
            specialkey : function (field, e) {
                if (e.getKey() == e.ENTER) {
                    _clickOnSearch();
                }
            }
        }
    });*/
    
    var ds = new Ext.data.JsonStore({
        url : uriSuggest,
        restful : true,
        root : 'data',
        fields : [ {
            name : 'field',
            type : 'string'
        }, {
            name : 'name',
            type : 'string'
        }, {
            name : 'nb',
            type : 'string'
        } ]
    });
    
    
    // Custom rendering Template
    var resultTpl = new Ext.XTemplate('<tpl for="."><div class="search-item">', '<h3>{name}<span> ({field} / {nb} results ) </span></h3>', '</div></tpl>');

    var search = new Ext.form.ComboBox({
        store : ds,
        displayField : 'name',
        typeAhead : false,
        loadingText : i18n.get("label.searching"),
        hideTrigger : true,
        fieldLabel : i18n.get("label.search"),
        name : 'searchQuery',
        anchor : "100%",
        tpl : resultTpl,
        itemSelector : 'div.search-item',
        minChars : 2,
        queryParam : 'q',
        enableKeyEvents : true,
        scope : this,
        listeners : {
            scope : this,
            beforequery : function (queryEvent) {
                if (queryEvent.query.indexOf(" ") == -1) {
                    return true;
                } else {
                    return false;
                }
            },
            specialkey : function (field, e) {
                if (e.getKey() == e.ENTER) {
                    _clickOnSearch();
                }
            },
            beforeselect : function (self, record, index) {
                record.data.name = record.data.field + ":" + record.data.name;
                return true;
            }

        }

    });
    
    
    this.storeCb = new Ext.data.ArrayStore({
        id: 0,
        fields: [            
            'nbResults'
        ],
        data: [[10], [20], [30], [40], [50]]
    });
    
 // create the combo instance
    var combo = new Ext.form.ComboBox({
        name: "nbResults",
        typeAhead: true,
        triggerAction: 'all',
        lazyRender: true,
        mode: 'local',
        store: this.storeCb,
        valueField: 'nbResults',
        displayField: 'nbResults',
        fieldLabel: i18n.get("label.nbResults"),
        value: this.storeCb.getAt(0).get("nbResults")
    });



    // set the items of the form
    var items = [ search, combo ];

    // set the search button
    var buttonForm = [ {
        text : i18n.get("label.search"),
        scope : this,
        handler : _clickOnSearch
    } ];

    // set the search form
    var formPanel = new Ext.FormPanel({
        labelWidth : 75, // label settings here cascade unless overridden
        height : 90,
        frame : true,
        defaultType : 'textfield',
        items : items,
        buttons : buttonForm

    });

    function clickOnRow(self, rowIndex, e) {
        var rec = self.store.getAt(rowIndex);
        var guid = rec.get("guid");
        if (Ext.isEmpty(guid)) {
            Ext.Msg.alert(i18n.get('label.warning'), i18n.get('warning.noGuidFieldDefined') + "<br/>" + i18n.get('warning.noPrimaryKeyDefinedOSNotice'));
            return;
        }
        var component = new sitools.user.component.simpleViewDataDetail({
            urlDataDetail : guid
        });
        var win = new Ext.Window({
            stateful : false,
            title : i18n.get('label.viewDataDetail'),
            width : 400,
            height : 600,
            shim : false,
            animCollapse : false,
            constrainHeader : true,
            layout : 'fit'
        });
        win.add(component);
        win.show();
    }


    // instanciate the RSS feed component
    var result = new sitools.user.component.openSearchResultFeed({
        input : search,
        dataUrl : config.dataUrl,
        pagging : false,
        listeners : {
            rowdblclick : clickOnRow
        }
    });

    // instanciate the panel component
    sitools.component.users.portal.portalOpensearch.superclass.constructor.call(this, Ext.apply({
        items : [ formPanel, result ],
        layout : 'vbox',
        layoutConfig : {
            align : 'stretch',
            pack : 'start'
        }

    }, config));

};

Ext.extend(sitools.component.users.portal.portalOpensearch, Ext.Panel, {});

Ext.reg('sitools.component.users.portal.portalOpensearch', sitools.component.users.portal.portalOpensearch);
/*******************************************************************************
 * Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
 * 
 * This file is part of SITools2.
 * 
 * SITools2 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SITools2 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SITools2. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
/*
 * global Ext, sitools, i18n, window, userLogin, projectGlobal, SitoolsDesk,
 * DEFAULT_PREFERENCES_FOLDER, loadUrl, onRequestFeedException
 */
/*
 * @include "../viewDataDetail/simpleViewDataDetails.js" @include
 * "../viewDataDetail/viewDataDetail.js"
 */

Ext.namespace('sitools.user.component');

/**
 * Component used to display opensearch results param : url : the url of the RSS
 * feed
 * 
 * @cfg {string} urlFeed the url of the feed
 * @cfg {string} input The input value to set
 * @cfg {boolean} autoLoad If the store needs to be loaded on start
 * @cfg {string} dataUrl the url of the dataset
 * @cfg {boolean} pagging true to activate the pagging, false otherwise
 * @cfg {} dsInfo informations about the dataset
 * @cfg {} exceptionHttpHandler the handler for httpProxy errors
 * @requires sitools.user.component.simpleViewDataDetail
 * @requires sitools.user.component.viewDataDetail
 * @class sitools.user.component.openSearchResultFeed
 * @extends Ext.grid.GridPanel
 */
sitools.user.component.openSearchResultFeed = function(config) {
	// sitools.component.users.datasets.openSearchResultFeed = function (config)
	// {
	this.pageSize = 10;
	var urlParam = config.urlFeed;
	this.input = config.input;
	this.uriRecords = config.dataUrl + "/records";
	var pagging = config.pagging;
	var url = (urlParam === undefined) ? "/tmp" : urlParam;

	var exceptionHttpHandler = (Ext.isEmpty(config.exceptionHttpHandler))
			? onRequestFeedException
			: config.exceptionHttpHandler;

	this.httpProxy = new Ext.data.HttpProxy({
				url : url,
				restful : true,
				listeners : {
					scope : this,
					exception : exceptionHttpHandler
				}
			});

	this.xmlReader = new sitools.component.users.datasets.XmlReader({
				record : 'item',
				totalProperty : 'opensearch:totalResults'
			}, ['title', 'link', 'guid', 'pubDate', 'description']);

	this.store = new Ext.data.Store({
				proxy : this.httpProxy,
				reader : this.xmlReader,
				autoLoad : config.autoLoad,
				paramNames : {
					start : 'start',
					limit : 'rows'
				},
				listeners : {
					scope : this,
					load : function(self, records, index) {
						if (!pagging && !Ext.isEmpty(this.displayNbResults)) {
							this.displayNbResults
									.setText('Total number of results : '
											+ this.store.getTotalCount());
							// this.getBottomToolbar().doLayout();
						}
						return true;
					},
					exception : function(proxy, type, action, options,
							response, arg) {
						var data = Ext.decode(response.responseText);
						if (!data.success) {
							this.input.markInvalid(i18n.get(data.message));
							this.store.removeAll();
						}
						return true;
					}
				}

			});

	this.store.setDefaultSort('pubDate', "DESC");

	// if (config.autoLoad !== null && config.autoLoad !== undefined &&
	// config.autoLoad) {
	// this.store.load();
	// }

	var columns = [{
				id : 'title',
				header : "Title",
				dataIndex : 'title',
				sortable : true,
				renderer : this.formatTitle
			}, {
				id : 'last',
				header : "Date",
				dataIndex : 'pubDate',
				renderer : this.formatDate,
				sortable : true

			}];

	if (pagging) {
		this.bbar = {
			xtype : 'paging',
			pageSize : this.pageSize,
			store : this.store,
			displayInfo : true,
			displayMsg : i18n.get('paging.display'),
			emptyMsg : i18n.get('paging.empty'),
			totalProperty : 'totalCount'
		};
	} else {
		this.displayNbResults = new Ext.form.Label({
					text : 'Total number of results : '
				});
		this.bbar = {
			items : ['->', this.displayNbResults

			]
		};
	}

	function clickOnRow(self, rowIndex, e) {
		e.stopEvent();
		var rec = self.store.getAt(rowIndex);
		var guid = rec.get("guid");
		if (Ext.isEmpty(guid)) {
			Ext.Msg.alert(i18n.get('label.warning'), i18n
							.get('warning.noGuidFieldDefined')
							+ "<br/>"
							+ i18n.get('warning.noPrimaryKeyDefinedOSNotice'));
			return;
		}
		// si on est pas sur le bureau
		if (Ext.isEmpty(window) || Ext.isEmpty(window.SitoolsDesk)) {
			var component = new sitools.user.component.simpleViewDataDetail({
						fromWhere : "openSearch",
						urlDataDetail : guid
					});
			var win = new Ext.Window({
						stateful : false,
						title : i18n.get('label.viewDataDetail'),
						width : 400,
						height : 600,
						shim : false,
						animCollapse : false,
						constrainHeader : true,
						layout : 'fit'
					});
			win.add(component);
			win.show();
		} else {
			var componentCfg = {
				grid : this,
				fromWhere : "openSearch",
				datasetId : config.datasetId,
				datasetUrl : config.dataUrl,
				datasetName : config.datasetName,
				preferencesPath : "/" + config.datasetName,
				preferencesFileName : "dataDetails"
			};
			var jsObj = sitools.user.component.viewDataDetail;

			var windowConfig = {
				id : "dataDetail" + config.datasetId,
				title : i18n.get('label.viewDataDetail') + " : "
						+ config.datasetName,
				datasetName : config.datasetName,
				iconCls : "openSearch",
				saveToolbar : true,
				type : "dataDetail",
				toolbarItems : [{
							iconCls : 'arrow-back',
							handler : function() {
								this.ownerCt.ownerCt.items.items[0]
										.goPrevious();
							}
						}, {
							iconCls : 'arrow-next',
							handler : function() {
								this.ownerCt.ownerCt.items.items[0].goNext();
							}
						}]
			};
			SitoolsDesk.addDesktopWindow(windowConfig, componentCfg, jsObj,
					true);
		}

	}

	sitools.user.component.openSearchResultFeed.superclass.constructor.call(
			this, {
				columns : columns,
				// hideHeaders : true,
				// region : 'center',
				layout : 'fit',
				flex : 1,
				store : this.store,
				loadMask : {
					msg : i18n.get("label.loadingFeed")
				},
				sm : new Ext.grid.RowSelectionModel({
							singleSelect : true
						}),
				autoExpandColumn : 'title',
				viewConfig : {
					forceFit : true,
					enableRowBody : true,
					showPreview : true,
					getRowClass : this.applyRowClass
				},
				listeners : {
					rowdblclick : clickOnRow
				}
			});

	this.updateStore = function(url) {
		this.httpProxy.setUrl(url, true);
		this.store.load();
	};

};

Ext.extend(sitools.user.component.openSearchResultFeed, Ext.grid.GridPanel, {
	componentType : "feeds",
	// within this function "this" is actually the GridView
	applyRowClass : function(record, rowIndex, p, ds) {
		if (this.showPreview) {
			var xf = Ext.util.Format;
			p.body = '<p class=sous-titre-flux>'
					+ xf.ellipsis(xf.stripTags(record.data.description), 200)
					+ '</p>';
			return 'x-grid3-row-expanded';
		}
		return 'x-grid3-row-collapsed';
	},

	formatDate : function(date) {
		if (!date) {
			return '';
		}
		var now = new Date();
		var d = now.clearTime(true);
		if (date instanceof Date) {
			var notime = date.clearTime(true).getTime();
			if (notime == d.getTime()) {
				return 'Today ' + date.dateFormat('g:i a');
			}
			d = d.add('d', -6);
			if (d.getTime() <= notime) {
				return date.dateFormat('D g:i a');
			}
			return date.dateFormat('n/j g:i a');
		} else {
			return date;
		}
	},

	/**
	 * Specific renderer for title Column
	 * 
	 * @param {}
	 *            value
	 * @param {}
	 *            p
	 * @param {Ext.data.Record}
	 *            record
	 * @return {string}
	 */
	formatTitle : function(value, p, record) {
		var link = record.data.link;
		var xf = Ext.util.Format;
		var res = "";
		if (link !== undefined && link !== "") {
			res = String
					.format(
							'<div class="topic"><a href="{0}" title="{1}"><span class="rss_feed_title">{2}</span></a></div>',
							link, value, xf.ellipsis(xf.stripTags(value), 30));
		} else {
			res = String
					.format(
							'<div class="topic"><span class="rss_feed_title">{0}</span></div>',
							xf.ellipsis(xf.stripTags(value), 30));
		}

		return res;
	}

});

Ext.reg('sitools.user.component.openSearchResultFeed',
		sitools.user.component.openSearchResultFeed);
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, ID, i18n, document, showResponse, alertFailure, window*/
/*!
 * Ext JS Library 3.3.1
 * Copyright(c) 2006-2010 Sencha Inc.
 * licensing@sencha.com
 * http://www.sencha.com/license
 */
/*
 * This is code is also distributed under MIT license for use
 * with jQuery and prototype JavaScript libraries.
 */
/**
 * @class sitools.component.users.datasets.DomQuery Provides high performance
 *        selector/xpath processing by compiling queries into reusable
 *        functions. New pseudo classes and matchers can be plugged. It works on
 *        HTML and XML documents (if a content node is passed in).
 * 
 * 
 * DomQuery supports most of the CSS3 selectors spec, along with some custom
 * selectors and basic XPath.
 * 
 * 
 * 
 * All selectors, attribute filters and pseudos below can be combined infinitely
 * in any order. For example "div.foo:nth-child(odd)[@foo=bar].bar:first" would
 * be a perfectly valid selector. Node filters are processed in the order in
 * which they appear, which allows you to optimize your queries for your
 * document structure.
 * 
 * Element Selectors:
 *  * any element
 * 
 * E an element with the tag E
 * 
 * E F All descendent elements of E that have the tag F
 * 
 * E > F or E/F all direct children elements of E that have the tag F
 * 
 * E + F all elements with the tag F that are immediately preceded by an element
 * with the tag E
 * 
 * E ~ F all elements with the tag F that are preceded by a sibling element with
 * the tag E
 * 
 * 
 * Attribute Selectors:
 * 
 * The use of @ and quotes are optional. For example, div[@foo='bar'] is also a
 * valid attribute selector.
 * 
 * 
 * E[foo] has an attribute "foo"
 * 
 * E[foo=bar] has an attribute "foo" that equals "bar"
 * 
 * E[foo^=bar] has an attribute "foo" that starts with "bar"
 * 
 * E[foo$=bar] has an attribute "foo" that ends with "bar"
 * 
 * E[foo*=bar] has an attribute "foo" that contains the substring "bar"
 * 
 * E[foo%=2] has an attribute "foo" that is evenly divisible by 2
 * 
 * E[foo!=bar] attribute "foo" does not equal "bar"
 * 
 * 
 * Pseudo Classes:
 * 
 * 
 * E:first-child E is the first child of its parent
 * 
 * E:last-child E is the last child of its parent
 * 
 * E:nth-child(n) E is the nth child of its parent (1 based as per the spec)
 * 
 * E:nth-child(odd) E is an odd child of its parent
 * 
 * E:nth-child(even) E is an even child of its parent
 * 
 * E:only-child E is the only child of its parent
 * 
 * E:checked E is an element that is has a checked attribute that is true (e.g.
 * a radio or checkbox)
 * 
 * E:first the first E in the resultset
 * 
 * E:last the last E in the resultset
 * 
 * E:nth(n) the nth E in the resultset (1 based)
 * 
 * E:odd shortcut for :nth-child(odd)
 * 
 * E:even shortcut for :nth-child(even)
 * 
 * E:contains(foo) E's innerHTML contains the substring "foo"
 * 
 * E:nodeValue(foo) E contains a textNode with a nodeValue that equals "foo"
 * 
 * E:not(S) an E element that does not match simple selector S
 * 
 * E:has(S) an E element that has a descendent that matches simple selector S
 * 
 * E:next(S) an E element whose next sibling matches simple selector S
 * 
 * E:prev(S) an E element whose previous sibling matches simple selector S
 * 
 * E:any(S1|S2|S2) an E element which matches any of the simple selectors S1, S2
 * or S3//\\
 * 
 * 
 * CSS Value Selectors:
 * 
 * 
 * E{display=none} css value "display" that equals "none"
 * 
 * E{display^=none} css value "display" that starts with "none"
 * 
 * E{display$=none} css value "display" that ends with "none"
 * 
 * E{display*=none} css value "display" that contains the substring "none"
 * 
 * E{display%=2} css value "display" that is evenly divisible by 2
 * 
 * E{display!=none} css value "display" that does not equal "none"
 * 
 * 
 * @singleton
 */
Ext.namespace("sitools.component.users.datasets");
sitools.component.users.datasets.DomQuery = function () {
    var cache = {}, simpleCache = {}, valueCache = {}, nonSpace = /\S/, trimRe = /^\s+|\s+$/g, tplRe = /\{(\d+)\}/g, modeRe = /^(\s?[\/>+~]\s?|\s|$)/, tagTokenRe = /^(#)?((?:opensearch:)?[\w-\*]+)/, nthRe = /(\d*)n\+?(\d*)/, nthRe2 = /\D/,
    // This is for IE MSXML which does not support expandos.
    // IE runs the same speed using setAttribute, however FF slows way down
    // and Safari completely fails so they need to continue to use expandos.
    isIE = window.ActiveXObject ? true : false, key = 30803;

    // this eval is stop the compressor from
    // renaming the variable to something shorter
    eval("var batch = 30803;");

    // Retrieve the child node from a particular
    // parent at the specified index.
    function child(parent, index) {
        var i = 0, n = parent.firstChild;
        while (n) {
            if (n.nodeType == 1) {
                if (++i == index) {
                    return n;
                }
            }
            n = n.nextSibling;
        }
        return null;
    }

    // retrieve the next element node
    function next(n) {
        while ((n = n.nextSibling) && n.nodeType != 1)
            ;
        return n;
    }

    // retrieve the previous element node
    function prev(n) {
        while ((n = n.previousSibling) && n.nodeType != 1)
            ;
        return n;
    }

    // Mark each child node with a nodeIndex skipping and
    // removing empty text nodes.
    function children (parent) {
        var n = parent.firstChild, nodeIndex = -1, nextNode;
        while (n) {
            nextNode = n.nextSibling;
            // clean worthless empty nodes.
            if (n.nodeType == 3 && !nonSpace.test(n.nodeValue)) {
                parent.removeChild(n);
            } else {
                // add an expando nodeIndex
                n.nodeIndex = ++nodeIndex;
            }
            n = nextNode;
        }
        return this;
    }

    // nodeSet - array of nodes
    // cls - CSS Class
    function byClassName (nodeSet, cls) {
        if (!cls) {
            return nodeSet;
        }
        var result = [], ri = -1;
        for ( var i = 0, ci; ci = nodeSet[i]; i++) {
            if ((' ' + ci.className + ' ').indexOf(cls) != -1) {
                result[++ri] = ci;
            }
        }
        return result;
    }
    ;

    function attrValue (n, attr) {
        // if its an array, use the first node.
        if (!n.tagName && typeof n.length != "undefined") {
            n = n[0];
        }
        if (!n) {
            return null;
        }

        if (attr == "for") {
            return n.htmlFor;
        }
        if (attr == "class" || attr == "className") {
            return n.className;
        }
        return n.getAttribute(attr) || n[attr];

    }
    ;

    // ns - nodes
    // mode - false, /, >, +, ~
    // tagName - defaults to "*"
    function getNodes (ns, mode, tagName) {
        var result = [], ri = -1, cs;
        if (!ns) {
            return result;
        }
        tagName = tagName || "*";
        // convert to array
        if (typeof ns.getElementsByTagName != "undefined") {
            ns = [ ns ];
        }

        // no mode specified, grab all elements by tagName
        // at any depth
        if (!mode) {
            for ( var i = 0, ni; ni = ns[i]; i++) {
                cs = ni.getElementsByTagName(tagName);
                for ( var j = 0, ci; ci = cs[j]; j++) {
                    result[++ri] = ci;
                }
            }
            // Direct Child mode (/ or >)
            // E > F or E/F all direct children elements of E that have the tag
        } else if (mode == "/" || mode == ">") {
            var utag = tagName.toUpperCase();
            for ( var i = 0, ni, cn; ni = ns[i]; i++) {
                cn = ni.childNodes;
                for ( var j = 0, cj; cj = cn[j]; j++) {
                    if (cj.nodeName == utag || cj.nodeName == tagName || tagName == '*') {
                        result[++ri] = cj;
                    }
                }
            }
            // Immediately Preceding mode (+)
            // E + F all elements with the tag F that are immediately preceded
            // by an element with the tag E
        } else if (mode == "+") {
            var utag = tagName.toUpperCase();
            for ( var i = 0, n; n = ns[i]; i++) {
                while ((n = n.nextSibling) && n.nodeType != 1)
                    ;
                if (n && (n.nodeName == utag || n.nodeName == tagName || tagName == '*')) {
                    result[++ri] = n;
                }
            }
            // Sibling mode (~)
            // E ~ F all elements with the tag F that are preceded by a sibling
            // element with the tag E
        } else if (mode == "~") {
            var utag = tagName.toUpperCase();
            for ( var i = 0, n; n = ns[i]; i++) {
                while ((n = n.nextSibling)) {
                    if (n.nodeName == utag || n.nodeName == tagName || tagName == '*') {
                        result[++ri] = n;
                    }
                }
            }
        }
        return result;
    }

    function concat (a, b) {
        if (b.slice) {
            return a.concat(b);
        }
        for ( var i = 0, l = b.length; i < l; i++) {
            a[a.length] = b[i];
        }
        return a;
    }

    function byTag (cs, tagName) {
        if (cs.tagName || cs == document) {
            cs = [ cs ];
        }
        if (!tagName) {
            return cs;
        }
        var result = [], ri = -1;
        tagName = tagName.toLowerCase();
        for ( var i = 0, ci; ci = cs[i]; i++) {
            if (ci.nodeType == 1 && ci.tagName.toLowerCase() == tagName) {
                result[++ri] = ci;
            }
        }
        return result;
    }

    function byId (cs, id) {
        if (cs.tagName || cs == document) {
            cs = [ cs ];
        }
        if (!id) {
            return cs;
        }
        var result = [], ri = -1;
        for ( var i = 0, ci; ci = cs[i]; i++) {
            if (ci && ci.id == id) {
                result[++ri] = ci;
                return result;
            }
        }
        return result;
    }

    // operators are =, !=, ^=, $=, *=, %=, |= and ~=
    // custom can be "{"
    function byAttribute (cs, attr, value, op, custom) {
        var result = [], ri = -1, useGetStyle = custom == "{", fn = sitools.component.users.datasets.DomQuery.operators[op], a, xml, hasXml;

        for ( var i = 0, ci; ci = cs[i]; i++) {
            // skip non-element nodes.
            if (ci.nodeType != 1) {
                continue;
            }
            // only need to do this for the first node
            if (!hasXml) {
                xml = sitools.component.users.datasets.DomQuery.isXml(ci);
                hasXml = true;
            }

            // we only need to change the property names if we're dealing with
            // html nodes, not XML
            if (!xml) {
                if (useGetStyle) {
                    a = sitools.component.users.datasets.DomQuery.getStyle(ci, attr);
                } else if (attr == "class" || attr == "className") {
                    a = ci.className;
                } else if (attr == "for") {
                    a = ci.htmlFor;
                } else if (attr == "href") {
                    // getAttribute href bug
                    // http://www.glennjones.net/Post/809/getAttributehrefbug.htm
                    a = ci.getAttribute("href", 2);
                } else {
                    a = ci.getAttribute(attr);
                }
            } else {
                a = ci.getAttribute(attr);
            }
            if ((fn && fn(a, value)) || (!fn && a)) {
                result[++ri] = ci;
            }
        }
        return result;
    }

    function byPseudo (cs, name, value) {
        return sitools.component.users.datasets.DomQuery.pseudos[name](cs, value);
    }

    function nodupIEXml (cs) {
        var d = ++key, r;
        cs[0].setAttribute("_nodup", d);
        r = [ cs[0] ];
        for ( var i = 1, len = cs.length; i < len; i++) {
            var c = cs[i];
            if (!c.getAttribute("_nodup") != d) {
                c.setAttribute("_nodup", d);
                r[r.length] = c;
            }
        }
        for ( var i = 0, len = cs.length; i < len; i++) {
            cs[i].removeAttribute("_nodup");
        }
        return r;
    }

    function nodup (cs) {
        if (!cs) {
            return [];
        }
        var len = cs.length, c, i, r = cs, cj, ri = -1;
        if (!len || typeof cs.nodeType != "undefined" || len == 1) {
            return cs;
        }
        if (isIE && typeof cs[0].selectSingleNode != "undefined") {
            return nodupIEXml(cs);
        }
        var d = ++key;
        cs[0]._nodup = d;
        for (i = 1; c = cs[i]; i++) {
            if (c._nodup != d) {
                c._nodup = d;
            } else {
                r = [];
                for ( var j = 0; j < i; j++) {
                    r[++ri] = cs[j];
                }
                for (j = i + 1; cj = cs[j]; j++) {
                    if (cj._nodup != d) {
                        cj._nodup = d;
                        r[++ri] = cj;
                    }
                }
                return r;
            }
        }
        return r;
    }

    function quickDiffIEXml (c1, c2) {
        var d = ++key, r = [];
        for ( var i = 0, len = c1.length; i < len; i++) {
            c1[i].setAttribute("_qdiff", d);
        }
        for ( var i = 0, len = c2.length; i < len; i++) {
            if (c2[i].getAttribute("_qdiff") != d) {
                r[r.length] = c2[i];
            }
        }
        for ( var i = 0, len = c1.length; i < len; i++) {
            c1[i].removeAttribute("_qdiff");
        }
        return r;
    }

    function quickDiff (c1, c2) {
        var len1 = c1.length, d = ++key, r = [];
        if (!len1) {
            return c2;
        }
        if (isIE && typeof c1[0].selectSingleNode != "undefined") {
            return quickDiffIEXml(c1, c2);
        }
        for ( var i = 0; i < len1; i++) {
            c1[i]._qdiff = d;
        }
        for ( var i = 0, len = c2.length; i < len; i++) {
            if (c2[i]._qdiff != d) {
                r[r.length] = c2[i];
            }
        }
        return r;
    }

    function quickId (ns, mode, root, id) {
        if (ns == root) {
            var d = root.ownerDocument || root;
            return d.getElementById(id);
        }
        ns = getNodes(ns, mode, "*");
        return byId(ns, id);
    }

    return {
        getStyle : function (el, name) {
            return Ext.fly(el).getStyle(name);
        },

        /**
         * Compiles a selector/xpath query into a reusable function. The
         * returned function takes one parameter "root" (optional), which is the
         * context node from where the query should start.
         * 
         * @param {String}
         *            selector The selector/xpath query
         * @param {String}
         *            type (optional) Either "select" (the default) or "simple"
         *            for a simple selector match
         * @return {Function}
         */
        compile : function (path, type) {
            type = type || "select";

            // setup fn preamble
            var fn = [ "var f = function(root){\n var mode; ++batch; var n = root || document;\n" ], mode, lastPath, matchers = sitools.component.users.datasets.DomQuery.matchers, matchersLn = matchers.length, modeMatch,
            // accept leading mode switch
            lmode = path.match(modeRe);

            if (lmode && lmode[1]) {
                fn[fn.length] = 'mode="' + lmode[1].replace(trimRe, "") + '";';
                path = path.replace(lmode[1], "");
            }

            // strip leading slashes
            while (path.substr(0, 1) == "/") {
                path = path.substr(1);
            }

            while (path && lastPath != path) {
                lastPath = path;
                var tokenMatch = path.match(tagTokenRe);
                if (type == "select") {
                    if (tokenMatch) {
                        // ID Selector
                        if (tokenMatch[1] == "#") {
                            fn[fn.length] = 'n = quickId(n, mode, root, "' + tokenMatch[2] + '");';
                        } else {
                            fn[fn.length] = 'n = getNodes(n, mode, "' + tokenMatch[2] + '");';
                        }
                        path = path.replace(tokenMatch[0], "");
                    } else if (path.substr(0, 1) != '@') {
                        fn[fn.length] = 'n = getNodes(n, mode, "*");';
                    }
                    // type of "simple"
                } else {
                    if (tokenMatch) {
                        if (tokenMatch[1] == "#") {
                            fn[fn.length] = 'n = byId(n, "' + tokenMatch[2] + '");';
                        } else {
                            fn[fn.length] = 'n = byTag(n, "' + tokenMatch[2] + '");';
                        }
                        path = path.replace(tokenMatch[0], "");
                    }
                }
                while (!(modeMatch = path.match(modeRe))) {
                    var matched = false;
                    for ( var j = 0; j < matchersLn; j++) {
                        var t = matchers[j];
                        var m = path.match(t.re);
                        if (m) {
                            fn[fn.length] = t.select.replace(tplRe, function (x, i) {
                                return m[i];
                            });
                            path = path.replace(m[0], "");
                            matched = true;
                            break;
                        }
                    }
                    // prevent infinite loop on bad selector
                    if (!matched) {
                        throw 'Error parsing selector, parsing failed at "' + path + '"';
                    }
                }
                if (modeMatch[1]) {
                    fn[fn.length] = 'mode="' + modeMatch[1].replace(trimRe, "") + '";';
                    path = path.replace(modeMatch[1], "");
                }
            }
            // close fn out
            fn[fn.length] = "return nodup(n);\n}";

            // eval fn and return it
            eval(fn.join(""));
            return f;
        },

        /**
         * Selects a group of elements.
         * 
         * @param {String}
         *            selector The selector/xpath query (can be a comma
         *            separated list of selectors)
         * @param {Node/String}
         *            root (optional) The start of the query (defaults to
         *            document).
         * @return {Array} An Array of DOM elements which match the selector. If
         *         there are no matches, and empty Array is returned.
         */
        jsSelect : function (path, root, type) {
            // set root to doc if not specified.
            path = path || "";
        	root = root || document;

            if (typeof root == "string") {
                root = document.getElementById(root);
            }
            var paths = path.split(","), results = [];

            // loop over each selector
            for ( var i = 0, len = paths.length; i < len; i++) {
                var subPath = paths[i].replace(trimRe, "");
                // compile and place in cache
                if (!cache[subPath]) {
                    cache[subPath] = sitools.component.users.datasets.DomQuery.compile(subPath);
                    if (!cache[subPath]) {
                        throw subPath + " is not a valid selector";
                    }
                }
                var result = cache[subPath](root);
                if (result && result != document) {
                    results = results.concat(result);
                }
            }

            // if there were multiple selectors, make sure dups
            // are eliminated
            if (paths.length > 1) {
                return nodup(results);
            }
            return results;
        },
        isXml : function (el) {
            var docEl = (el ? el.ownerDocument || el : 0).documentElement;
            return docEl ? docEl.nodeName !== "HTML" : false;
        },
        select : document.querySelectorAll ? function (path, root, type) {
            root = root || document;
            if (!sitools.component.users.datasets.DomQuery.isXml(root)) {
                try {
                    var cs = root.querySelectorAll(path);
                    return Ext.toArray(cs);
                } catch (ex) {
                }
            }
            return sitools.component.users.datasets.DomQuery.jsSelect.call(this, path, root, type);
        } : function (path, root, type) {
            return sitools.component.users.datasets.DomQuery.jsSelect.call(this, path, root, type);
        },

        /**
         * Selects a single element.
         * 
         * @param {String}
         *            selector The selector/xpath query
         * @param {Node}
         *            root (optional) The start of the query (defaults to
         *            document).
         * @return {Element} The DOM element which matched the selector.
         */
        selectNode : function (path, root) {
            return sitools.component.users.datasets.DomQuery.select(path, root)[0];
        },

        /**
         * Selects the value of a node, optionally replacing null with the
         * defaultValue.
         * 
         * @param {String}
         *            selector The selector/xpath query
         * @param {Node}
         *            root (optional) The start of the query (defaults to
         *            document).
         * @param {String}
         *            defaultValue
         * @return {String}
         */
        selectValue : function (path, root, defaultValue) {
            path = path.replace(trimRe, "");
            if (!valueCache[path]) {
                valueCache[path] = sitools.component.users.datasets.DomQuery.compile(path, "select");
            }
            var n = valueCache[path](root), v;
            n = n[0] ? n[0] : n;

            // overcome a limitation of maximum textnode size
            // Rumored to potentially crash IE6 but has not been confirmed.
            // http://reference.sitepoint.com/javascript/Node/normalize
            // https://developer.mozilla.org/En/DOM/Node.normalize
            if (typeof n.normalize == 'function')
                n.normalize();

            v = (n && n.firstChild ? n.firstChild.nodeValue : null);
            return ((v === null || v === undefined || v === '') ? defaultValue : v);
        },

        /**
         * Selects the value of a node, parsing integers and floats. Returns the
         * defaultValue, or 0 if none is specified.
         * 
         * @param {String}
         *            selector The selector/xpath query
         * @param {Node}
         *            root (optional) The start of the query (defaults to
         *            document).
         * @param {Number}
         *            defaultValue
         * @return {Number}
         */
        selectNumber : function (path, root, defaultValue) {
            var v = sitools.component.users.datasets.DomQuery.selectValue(path, root, defaultValue || 0);
            return parseFloat(v);
        },

        /**
         * Returns true if the passed element(s) match the passed simple
         * selector (e.g. div.some-class or span:first-child)
         * 
         * @param {String/HTMLElement/Array}
         *            el An element id, element or array of elements
         * @param {String}
         *            selector The simple selector to test
         * @return {Boolean}
         */
        is : function (el, ss) {
            if (typeof el == "string") {
                el = document.getElementById(el);
            }
            var isArray = Ext.isArray(el), result = sitools.component.users.datasets.DomQuery.filter(isArray ? el : [ el ], ss);
            return isArray ? (result.length == el.length) : (result.length > 0);
        },

        /**
         * Filters an array of elements to only include matches of a simple
         * selector (e.g. div.some-class or span:first-child)
         * 
         * @param {Array}
         *            el An array of elements to filter
         * @param {String}
         *            selector The simple selector to test
         * @param {Boolean}
         *            nonMatches If true, it returns the elements that DON'T
         *            match the selector instead of the ones that match
         * @return {Array} An Array of DOM elements which match the selector. If
         *         there are no matches, and empty Array is returned.
         */
        filter : function (els, ss, nonMatches) {
            ss = ss.replace(trimRe, "");
            if (!simpleCache[ss]) {
                simpleCache[ss] = sitools.component.users.datasets.DomQuery.compile(ss, "simple");
            }
            var result = simpleCache[ss](els);
            return nonMatches ? quickDiff(result, els) : result;
        },

        /**
         * Collection of matching regular expressions and code snippets. Each
         * capture group within () will be replace the {} in the select
         * statement as specified by their index.
         */
        matchers : [ {
            re : /^\.([\w-]+)/,
            select : 'n = byClassName(n, " {1} ");'
        }, {
            re : /^\:([\w-]+)(?:\(((?:[^\s>\/]*|.*?))\))?/,
            select : 'n = byPseudo(n, "{1}", "{2}");'
        }, {
            re : /^(?:([\[\{])(?:@)?([\w-]+)\s?(?:(=|.=)\s?['"]?(.*?)["']?)?[\]\}])/,
            select : 'n = byAttribute(n, "{2}", "{4}", "{3}", "{1}");'
        }, {
            re : /^#([\w-]+)/,
            select : 'n = byId(n, "{1}");'
        }, {
            re : /^@([\w-]+)/,
            select : 'return {firstChild:{nodeValue:attrValue(n, "{1}")}};'
        } ],

        /**
         * Collection of operator comparison functions. The default operators
         * are =, !=, ^=, $=, *=, %=, |= and ~=. New operators can be added as
         * long as the match the format c= where c is any character other than
         * space, > <.
         */
        operators : {
            "=" : function (a, v) {
                return a == v;
            },
            "!=" : function (a, v) {
                return a != v;
            },
            "^=" : function (a, v) {
                return a && a.substr(0, v.length) == v;
            },
            "$=" : function (a, v) {
                return a && a.substr(a.length - v.length) == v;
            },
            "*=" : function (a, v) {
                return a && a.indexOf(v) !== -1;
            },
            "%=" : function (a, v) {
                return (a % v) == 0;
            },
            "|=" : function (a, v) {
                return a && (a == v || a.substr(0, v.length + 1) == v + '-');
            },
            "~=" : function (a, v) {
                return a && (' ' + a + ' ').indexOf(' ' + v + ' ') != -1;
            }
        },

        /**
         * 
         * 
         * Object hash of "pseudo class" filter functions which are used when
         * filtering selections. Each function is passed two parameters:
         *  * c : Array An Array of DOM elements to filter. * v : String The
         * argument (if any) supplied in the selector.
         * 
         * 
         * 
         * 
         * 
         * 
         * A filter function returns an Array of DOM elements which conform to
         * the pseudo class.
         * 
         * 
         * 
         * In addition to the provided pseudo classes listed above such as
         * first-child and nth-child, developers may add additional, custom
         * psuedo class filters to select elements according to
         * application-specific requirements.
         * 
         * 
         * 
         * For example, to filter <a> elements to only return links to external
         * resources:
         * 
         * 
         * 
         * sitools.component.users.datasets.DomQuery.pseudos.external =
         * function(c, v){ var r = [], ri = -1; for(var i = 0, ci; ci = c[i];
         * i++){ // Include in result set only if it's a link to an external
         * resource if(ci.hostname != location.hostname){ r[++ri] = ci; } }
         * return r; };
         * 
         * 
         * Then external links could be gathered with the following statement:
         * 
         * var externalLinks = Ext.select("a:external");
         * 
         * 
         */
        pseudos : {
            "first-child" : function (c) {
                var r = [], ri = -1, n;
                for ( var i = 0, ci; ci = n = c[i]; i++) {
                    while ((n = n.previousSibling) && n.nodeType != 1)
                        ;
                    if (!n) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "last-child" : function (c) {
                var r = [], ri = -1, n;
                for ( var i = 0, ci; ci = n = c[i]; i++) {
                    while ((n = n.nextSibling) && n.nodeType != 1)
                        ;
                    if (!n) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "nth-child" : function (c, a) {
                var r = [], ri = -1, m = nthRe.exec(a == "even" && "2n" || a == "odd" && "2n+1" || !nthRe2.test(a) && "n+" + a || a), f = (m[1] || 1) - 0, l = m[2] - 0;
                for ( var i = 0, n; n = c[i]; i++) {
                    var pn = n.parentNode;
                    if (batch != pn._batch) {
                        var j = 0;
                        for ( var cn = pn.firstChild; cn; cn = cn.nextSibling) {
                            if (cn.nodeType == 1) {
                                cn.nodeIndex = ++j;
                            }
                        }
                        pn._batch = batch;
                    }
                    if (f == 1) {
                        if (l == 0 || n.nodeIndex == l) {
                            r[++ri] = n;
                        }
                    } else if ((n.nodeIndex + l) % f == 0) {
                        r[++ri] = n;
                    }
                }

                return r;
            },

            "only-child" : function (c) {
                var r = [], ri = -1;
                ;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    if (!prev(ci) && !next(ci)) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "empty" : function (c) {
                var r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    var cns = ci.childNodes, j = 0, cn, empty = true;
                    while (cn = cns[j]) {
                        ++j;
                        if (cn.nodeType == 1 || cn.nodeType == 3) {
                            empty = false;
                            break;
                        }
                    }
                    if (empty) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "contains" : function (c, v) {
                var r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    if ((ci.textContent || ci.innerText || '').indexOf(v) != -1) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "nodeValue" : function (c, v) {
                var r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    if (ci.firstChild && ci.firstChild.nodeValue == v) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "checked" : function (c) {
                var r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    if (ci.checked == true) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "not" : function (c, ss) {
                return sitools.component.users.datasets.DomQuery.filter(c, ss, true);
            },

            "any" : function (c, selectors) {
                var ss = selectors.split('|'), r = [], ri = -1, s;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    for ( var j = 0; s = ss[j]; j++) {
                        if (sitools.component.users.datasets.DomQuery.is(ci, s)) {
                            r[++ri] = ci;
                            break;
                        }
                    }
                }
                return r;
            },

            "odd" : function (c) {
                return this["nth-child"](c, "odd");
            },

            "even" : function (c) {
                return this["nth-child"](c, "even");
            },

            "nth" : function (c, a) {
                return c[a - 1] || [];
            },

            "first" : function (c) {
                return c[0] || [];
            },

            "last" : function (c) {
                return c[c.length - 1] || [];
            },

            "has" : function (c, ss) {
                var s = sitools.component.users.datasets.DomQuery.select, r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    if (s(ss, ci).length > 0) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "next" : function (c, ss) {
                var is = sitools.component.users.datasets.DomQuery.is, r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    var n = next(ci);
                    if (n && is(n, ss)) {
                        r[++ri] = ci;
                    }
                }
                return r;
            },

            "prev" : function (c, ss) {
                var is = sitools.component.users.datasets.DomQuery.is, r = [], ri = -1;
                for ( var i = 0, ci; ci = c[i]; i++) {
                    var n = prev(ci);
                    if (n && is(n, ss)) {
                        r[++ri] = ci;
                    }
                }
                return r;
            }
        }
    };
}();

/**
 * Selects an array of DOM nodes by CSS/XPath selector. Shorthand of
 * {@link sitools.component.users.datasets.DomQuery#select}
 * 
 * @param {String}
 *            path The selector/xpath query
 * @param {Node}
 *            root (optional) The start of the query (defaults to document).
 * @return {Array}
 * @member Ext
 * @method query
 */
Ext.query = sitools.component.users.datasets.DomQuery.select;
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n, window*/
Ext.namespace('sitools.component.users.datasets');

sitools.component.users.datasets.XmlReader = function (meta, recordType) {
    meta = meta || {};

    // backwards compat, convert idPath or id / success
    Ext.applyIf(meta, {
        idProperty : meta.idProperty || meta.idPath || meta.id,
        successProperty : meta.successProperty || meta.success
    });

    sitools.component.users.datasets.XmlReader.superclass.constructor.call(this, meta, recordType || meta.fields);
};
Ext.extend(sitools.component.users.datasets.XmlReader, Ext.data.XmlReader, {

    /**
     * Creates a function to return some particular key of data from a response.
     * 
     * @param {String}
     *            key
     * @return {Function}
     * @private
     * @ignore
     */
    createAccessor : function () {
        var q = sitools.component.users.datasets.DomQuery;
        return function (key) {
            if (Ext.isFunction(key)) {
                return key;
            }
            switch (key) {
            case this.meta.totalProperty:
                return function (root, def) {
                    return q.selectNumber(key, root, def);
                };
                break;
            case this.meta.successProperty:
                return function (root, def) {
                    var sv = q.selectValue(key, root, true);
                    var success = sv !== false && sv !== 'false';
                    return success;
                };
                break;
            default:
                return function (root, def) {
                    return q.selectValue(key, root, def);
                };
                break;
            }
        };
    }()

});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n, alertFailure, window, loadUrl, sql2ext, SITOOLS_DEFAULT_IHM_DATE_FORMAT, ColumnRendererEnum, SITOOLS_DATE_FORMAT*/

Ext.namespace('sitools.user.component');

/**
 * Data detail Panel view. 
 * 
 * @cfg {string} fromWhere (required) :  "Ext.ux.livegrid" or "openSearch", "plot", "dataView"
 *       used to know how to determine the Url of the record
 * @cfg grid : the grid that contains all the datas 
 * @cfg {string} baseUrl  used only in "data" case. 
 *       used to build the url of the record. Contains datasetAttachement + "/records"
 * @cfg {string} datasetId the datasetId
 * @cfg {string} datasetUrl the dataset url attachment
 * @class sitools.user.component.viewDataDetail
 * @extends Ext.Panel
 */
sitools.user.component.viewDataDetail = Ext.extend(Ext.Panel, {
//sitools.component.users.viewDataDetail = Ext.extend(Ext.Panel, {
	datasetColumnModel : null,
    initComponent : function () {
        var rec;
        switch (this.fromWhere) {
		case "openSearch" : 
	        this.recSelected = this.grid.getSelectionModel().getSelected();
	        this.url = this.encodeUrlPrimaryKey(this.recSelected.data.guid);	        
			break;
		case "dataView" : 
			break;
        case "plot" : 
            break;
		default : 
			this.recSelected = this.selections[0];
	        if (Ext.isEmpty(this.recSelected)) {
				Ext.Msg.alert(i18n.get('label.error'), i18n.get('label.noSelection'));
				return;
	        }
	        var primaryKeyValue = "", primaryKeyName = "";
	        Ext.each(this.recSelected.fields.items, function (field) {
	            if (field.primaryKey) {
	                this.primaryKeyName = field.name;
	            }
	        }, this);
	        
			this.primaryKeyValue = this.recSelected.get(this.primaryKeyName);
	        
	        this.primaryKeyValue = encodeURIComponent(this.primaryKeyValue);
	        
	        this.url = this.baseUrl + this.primaryKeyValue;
			break;
        }
        
        
        this.layout = "border";

        this.linkStore = new Ext.data.Store({
	        fields : [ 'name', 'value', 'image', 'behavior', 'columnRenderer', 'html']
	    }); 
        
        var linkDataview = new Ext.DataView({
	        store : this.linkStore, 
	        tpl : new Ext.XTemplate('<ul>', '<tpl for=".">', 
	                '<li id="{name}" class="img-link"',
	                '<tpl if="this.hasToolTip(toolTip)">',
	                    'ext:qtip="{toolTip}">', 
	                '</tpl>',
	                '<tpl if="this.hasToolTip(toolTip) == false">',
                        'ext:qtip="{name}">', 
                    '</tpl>',
                    '{html}',
	                '</li>', '</tpl>', '</ul>', 
	                {
	                compiled : true, 
	                disableFormats : true,
	                hasToolTip : function (toolTip) {
	                    return !Ext.isEmpty(toolTip);
	                }
	            }),
	        cls : 'linkImageDataView',
	        itemSelector : 'li.img-link',
	        overClass : 'nodes-hover',
            selectedClass : '',
	        singleSelect : true,
	        multiSelect : false,
	        autoScroll : true,
	        listeners : {
	            scope : this,
	            click : this.handleClickOnLink	
	        }
	    });
        
        
        // set the text form
        this.formPanel = new Ext.FormPanel({
            labelAlign : "top",
            anchor : "100%",
            defaults : {
                labelStyle: 'font-weight:bold;'
            },
            padding : 10
            
        });
        
        // set the text form
        this.linkPanel = new Ext.Panel({
            title : i18n.get("label.complementaryInformation"),
            items : [linkDataview],
            anchor : "100%"
        });
        
        // set the search form
        this.formPanelImg = new Ext.FormPanel({
            frame : true,
            autoScroll : true,
            region : "east", 
            hideLabels : true,
            split : (this.fromWhere !== 'dataView'), 
            collapsible : (this.fromWhere !== 'dataView'), 
//            collapsed : (this.fromWhere !== 'dataView'),
            collapsed : false,
            flex : 1,
            title : ((this.fromWhere === 'dataView') ? i18n.get("label.formImagePanelTitle") : null),
            listeners : {
                scope : this,
                expand : function (panel) {
                    
                } 
            }
        });
        
        var centerPanelItems;
        if (this.fromWhere === 'dataView') {
            centerPanelItems = [this.formPanel, this.formPanelImg, this.linkPanel];
        }
        else {
            centerPanelItems = [this.formPanel, this.linkPanel];
        }
        
        //set the center Panel
        this.centerPanel = new Ext.Panel({
            autoScroll : true,
            frame : true,
            region : "center", 
            split : true, 
            layout : {
                type : 'anchor'             
            },
            items : centerPanelItems
        });

       
        this.getCmDefAndbuildForm();
        
        this.componentType = 'dataDetail';
        if (this.fromWhere == 'dataView') {
			this.items = [this.centerPanel];
        }
        else {
			this.items = [ this.centerPanel, this.formPanelImg ];
        }

        this.listeners = {
			scope : this, 
			afterrender : function (panel) {
				panel.getEl().on("contextmenu", function (e, t, o) {
					e.stopPropagation();
				}, this);
			}
        };
        sitools.user.component.viewDataDetail.superclass.initComponent.call(this);
    }, 
    
    afterRender : function () {
        this._loadMaskAnchor = Ext.get(this.body.dom);
	    
        sitools.user.component.viewDataDetail.superclass.afterRender.apply(this, arguments);
       
        
        
    },
    /**
     * Need to save the window Settings
     * @return {}
     */
    _getSettings : function () {
        return {
            objectName : "viewDataDetail", 
            preferencesPath : this.preferencesPath, 
            preferencesFileName : this.preferencesFileName
        };
    }, 
    /**
     * Go to the Next record of the grid passed into parameters
     */
    goNext : function () {
		if (Ext.isEmpty(this.grid)) {
			return;
		}
		var rec, rowSelect;
		switch (this.fromWhere) {
		case "openSearch" : 
			rowSelect = this.grid.getSelectionModel();
	        if (! rowSelect.selectNext()) {
	            return;
	        }
	        rec = rowSelect.getSelected();
			this.url = this.encodeUrlPrimaryKey(rec.data.guid);
			break;
		case "sitools.user.component.dataviews.tplView.TplView" : 
			var index = this.grid.getStore().indexOf(this.recSelected);
			var nextRec = this.grid.getStore().getAt(index + 1);
			if (Ext.isEmpty(nextRec)) {
				return;
			}
			this.primaryKeyValue = nextRec.get(this.primaryKeyName);
            this.primaryKeyValue = encodeURIComponent(this.primaryKeyValue);
            this.url = this.baseUrl + this.primaryKeyValue;
			this.recSelected = nextRec;
            this.grid.select(nextRec);
			break;
		default : 
			rowSelect = this.grid.getSelectionModel();
	        if (! rowSelect.selectNext()) {
	            return;
	        }
	        rec = rowSelect.getSelected();
            this.primaryKeyValue = rec.get(this.primaryKeyName);
            this.primaryKeyValue = encodeURIComponent(this.primaryKeyValue);
            this.url = this.baseUrl + this.primaryKeyValue;
			break;
		}

        this.getCmDefAndbuildForm();	
    }, 
    /**
     * Go to the Previous record of the grid passed into parameters
     */
    goPrevious : function () {
		if (Ext.isEmpty(this.grid)) {
			return;
		}
		var rec, rowSelect;
		switch (this.fromWhere) {
		case "openSearch" : 
			rowSelect = this.grid.getSelectionModel();
	        if (! rowSelect.selectPrevious()) {
	            return;
	        }
	        rec = rowSelect.getSelected();
            this.url = this.encodeUrlPrimaryKey(rec.data.guid);
            break;
		case "sitools.user.component.dataviews.tplView.TplView" : 
			var index = this.grid.getStore().indexOf(this.recSelected);
			var nextRec = this.grid.getStore().getAt(index - 1);
			if (Ext.isEmpty(nextRec)) {
				return;
			}
			this.primaryKeyValue = nextRec.get(this.primaryKeyName);
            this.primaryKeyValue = encodeURIComponent(this.primaryKeyValue);
            this.url = this.baseUrl + this.primaryKeyValue;
			this.recSelected = nextRec;
            this.grid.select(nextRec);
			break;
		default : 
			rowSelect = this.grid.getSelectionModel();
	        if (! rowSelect.selectPrevious()) {
	            return;
	        }
	        rec = rowSelect.getSelected();
            this.primaryKeyValue = rec.get(this.primaryKeyName);
            this.primaryKeyValue = encodeURIComponent(this.primaryKeyValue);
            this.url = this.baseUrl + this.primaryKeyValue;
			break;
		}

        this.getCmDefAndbuildForm();	    
       
    }, 
    /**
     * Build the form according with the values loaded via the Url
     */
    getCmDefAndbuildForm : function () {
        if (Ext.isEmpty(this.datasetColumnModel)) {
		    Ext.Ajax.request({
	            url : this.datasetUrl,
	            method : 'GET',
	            scope : this,
	            success : function (ret) {
					try {
						var Json = Ext.decode(ret.responseText);
						if (!Json.success) {
							throw Json.message;
						}
						this.datasetColumnModel = Json.dataset.columnModel;
						this.buildForm();
					}
					catch (err) {
						Ext.Msg.alert(i18n.get('label.error'), err);
					}
					
	            }, 
	            failure : alertFailure
	        });        
	    }
	    else {
			this.buildForm();
	    }
    }, 
    buildForm : function () {
        
	    if (!Ext.isEmpty(this._loadMaskAnchor)) {
            this._loadMaskAnchor.mask(i18n.get('label.waitMessage'), "x-mask-loading");
        }

        if (!Ext.isEmpty(this.url)) {
            this.linkStore.removeAll();
	        Ext.Ajax.request({
	            url : this.url,
	            method : 'GET',
	            scope : this,
	            success : function (ret) {
	                var data = Ext.decode(ret.responseText);
	                var itemsForm = [];
	                var itemsFormImg = [];
	                if (!data.success) {
	                    Ext.Msg.alert(i18n.get('label.information'), "Server error");
	                    return false;
	                }
	                var record = data.record;
	                var id = record.id;
	                var attributes = record.attributeValues;
	                if (attributes !== undefined) {
	                    var i;
	                    for (i = 0; i < attributes.length; i++) {
	                        var name = attributes[i].name;
	                        
	                        var column = this.findColumn(name);
	                        var value = attributes[i].value;
	                        var valueFormat = value;
	                        
	                        if (sql2ext.get(column.sqlColumnType) == 'dateAsString') {
				                valueFormat = sitools.user.component.dataviews.dataviewUtils.formatDate(value, column);
				            }
				            if (sql2ext.get(column.sqlColumnType) == 'boolean') {
				                valueFormat = value ? i18n.get('label.true') : i18n.get('label.false');
				            }
	                        
	                        var item = new Ext.BoxComponent({
                                fieldLabel : column.header,
                                labelSeparator : "", 
                                html : (Ext.isEmpty(valueFormat) || !Ext.isFunction(valueFormat.toString))
												? valueFormat
												: valueFormat.toString()
                            });
	                        
	                        if (Ext.isEmpty(column) || Ext.isEmpty(column.columnRenderer)) {
		                        itemsForm.push(item);                                
		                    }
		                    else {
                                var columnRenderer = column.columnRenderer;
                                var behavior = "";
                                if (!Ext.isEmpty(column.columnRenderer)) {
                                    behavior = column.columnRenderer.behavior;
                                    var html = sitools.user.component.dataviews.dataviewUtils.getRendererHTML(column, {});
									switch (behavior) {
									case ColumnRendererEnum.URL_LOCAL :
					                case ColumnRendererEnum.URL_EXT_NEW_TAB :
					                case ColumnRendererEnum.URL_EXT_DESKTOP :
					                case ColumnRendererEnum.DATASET_ICON_LINK :
										if (! Ext.isEmpty(value)) {
	                                        if (!Ext.isEmpty(columnRenderer.linkText)) {
	                                            item = new Ext.BoxComponent({
		                                            fieldLabel : column.header,
					                                labelSeparator : "", 
		                                            html : String.format(html, value)
		                                        });	                                         
	                                            itemsForm.push(item);
							                } else if (!Ext.isEmpty(columnRenderer.image)) {
							                    var rec = {
	                                                name : name,
	                                                value : value,
	                                                image : columnRenderer.image.url,
	                                                behavior : behavior,
                                                    columnRenderer : columnRenderer,
                                                    toolTip : columnRenderer.toolTip,
                                                    html : html
                                                    
	                                            };
	                                            rec = new Ext.data.Record(rec);
	                                            this.linkStore.add(rec);                                            
							                }																	
										}                                    
										break;
	                                case ColumnRendererEnum.IMAGE_FROM_SQL : 
                                    case ColumnRendererEnum.IMAGE_THUMB_FROM_IMAGE :
	                                    if (! Ext.isEmpty(value)) {
	                                        var tooltip = "";
	                                        var imageUrl = "";
	                                        

	                                        if (!Ext.isEmpty(columnRenderer.toolTip)) {
	                                            tooltip = columnRenderer.toolTip;
	                                        }
	                                        else {
	                                            tooltip = column.header;
	                                        }
	                                        
						                    if (!Ext.isEmpty(columnRenderer.url)) {
						                        imageUrl = columnRenderer.url;
						                    } else if (!Ext.isEmpty(columnRenderer.columnAlias)) {
						                        imageUrl = this.findRecordValue(record, columnRenderer.columnAlias);            
						                    }
	                                        item = new Ext.BoxComponent({
	                                            html : String.format(html, value, imageUrl),
                                                tooltip : tooltip,
	                                            cls : "x-form-item"
	                                        });                                       
	                                    }
	                                    itemsFormImg.push(item);
	                                    break;
                                    case ColumnRendererEnum.NO_CLIENT_ACCESS :
                                        break;
									default : 
                                        item = new Ext.BoxComponent({
	                                        fieldLabel : column.header,
			                                labelSeparator : "", 
	                                        html : String.format(html, value)
	                                    });                                          
	                                    itemsForm.push(item);
	                                    break;
                                    }
		                        }
		                    }
                        }
	                    this.formPanel.removeAll();
	                    this.formPanelImg.removeAll();
	                    
                        this.formPanel.add(itemsForm);
	                    this.formPanel.doLayout();
                        
                        if (this.linkStore.getCount() === 0) {
                            this.linkPanel.setVisible(false);
                        } else {
                            this.linkPanel.setVisible(true);
                            this.linkPanel.doLayout();
                        }
                        
                        if (itemsFormImg.length === 0) {
                            this.formPanelImg.setVisible(false);
                        } else {
                            this.formPanelImg.add(itemsFormImg);
                            this.formPanelImg.setVisible(true);
                            this.linkPanel.doLayout();
                        }
                        
                        this.formPanelImg.doLayout();
	                    this.doLayout();
	                    if (this._loadMaskAnchor && this._loadMaskAnchor.isMasked()) {
							this._loadMaskAnchor.unmask();
						}
	                    
	                    //Register events on column values with featureTypes  
	                    this.registerClickEvent(attributes);
	                    
                    }
	            },
	            failure : function () {
	                alertFailure();
                    if (this._loadMaskAnchor && this._loadMaskAnchor.isMasked()) {
						this._loadMaskAnchor.unmask();
					}
	            }
	        });
	    }
    }, 
    findColumn : function (columnAlias) {
		var result = null;
		Ext.each(this.datasetColumnModel, function (column) {
			if (column.columnAlias == columnAlias) {
				result = column;
				return;
			}
		}, this);
		return result;
    },
    
    findRecordValue : function (record, columnAlias) {
        var result = null;
        Ext.each(record.attributeValues, function (attr) {
            if (attr.name == columnAlias) {
                result = attr.value;
                return;
            }
        }, this);
        return result;
    },
    
    handleClickOnLink : function (dataView, index, node, e) {
        var data = dataView.getRecord(node).data;
        var behavior = data.behavior;
        switch (behavior) {
        case ColumnRendererEnum.URL_LOCAL:
            sitools.user.component.dataviews.dataviewUtils.downloadData(data.value);
            break;
        case ColumnRendererEnum.URL_EXT_NEW_TAB  :
            window.open(data.value);
            break;
        case ColumnRendererEnum.URL_EXT_DESKTOP  :
            sitools.user.component.dataviews.dataviewUtils.showDisplayableUrl(data.value, data.columnRenderer.displayable);
            break;
        case ColumnRendererEnum.DATASET_ICON_LINK  :
            sitools.user.component.dataviews.dataviewUtils.showDetailsData(data.value, data.columnRenderer.columnAlias, data.columnRenderer.datasetLinkUrl);
            break;    
        default : 
            break;
            
        }
    }, 
    /**
     * Method called when trying to show this component with fixed navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInFixedNav : function (me, config) {
        Ext.apply(config.windowSettings, {
			width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
			height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
		});
        SitoolsDesk.openModalWindow(me, config);
    }, 
    /**
     * Method called when trying to show this component with Desktop navigation
     * 
     * @param {sitools.user.component.viewDataDetail} me the dataDetail view
     * @param {} config config options
     * @returns
     */
    showMeInDesktopNav : function (me, config) {
        Ext.apply(config.windowSettings, {
            width : config.windowSettings.winWidth || DEFAULT_WIN_WIDTH,
            height : config.windowSettings.winHeight || DEFAULT_WIN_HEIGHT
        });
        SitoolsDesk.openModalWindow(me, config);
    },
    
    encodeUrlPrimaryKey : function (url) {
      //get the end of the uri and encode it
        var urlSplited = url.split('/');
        var urlReturn = "";
        for (var i = 0; i < urlSplited.length; i++) {
            if (i < urlSplited.length - 1) {
                urlReturn += urlSplited[i] + "/";
            } else {
                urlReturn += encodeURIComponent(urlSplited[i]);
            }
        }
        return urlReturn;
    },
    
    callbackClickFeatureType : function (e, t, o) {
        e.stopEvent();
        var record = o.record;
        var controller = o.controller;            
        var column = o.column;
        sitools.user.component.dataviews.dataviewUtils.featureTypeAction(column, record, controller);
    },
    
    
    registerClickEvent : function (attributes) {
        
        var nodeFormPanel = this.formPanel.getEl().dom;
        var featureTypeNodes = Ext.DomQuery.jsSelect(".featureType", nodeFormPanel);
        
        var formPanelImgPanel = this.formPanelImg.getEl().dom;
        featureTypeNodes = featureTypeNodes.concat(Ext.DomQuery.jsSelect(".featureType", formPanelImgPanel));

        var linkImagePanel = this.linkPanel.getEl().dom;
        featureTypeNodes = featureTypeNodes.concat(Ext.DomQuery.jsSelect(".featureType", linkImagePanel));
        
        var controller = this.grid.getTopToolbar().guiServiceController;
        
        //Create a Record from the attribute Values 
        var jsonObj = {};
        Ext.each(attributes, function (attribute) {
            jsonObj[attribute.name] = attribute.value;
        });
        
        
        Ext.each(featureTypeNodes, function (featureTypeNode) {
            var featureTypeNodeElement = Ext.get(featureTypeNode);
            
            var columnAlias = featureTypeNodeElement.getAttribute("column", "sitools");
            var column = this.findColumn(columnAlias);
            
            featureTypeNodeElement.addListener("click", this.callbackClickFeatureType, this, {
                record : new Ext.data.Record(jsonObj),
                controller : controller,
                column : column
            });
        }, this);
            

        if (this.formPanelImg.collapsible && this.formPanelImg.isVisible()) {    
            this.formPanelImg.collapse();
        }
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, i18n, alertFailure*/

Ext.namespace('sitools.user.component');

/**
 * A simple form view to visualize a record. 
 * Builds a form Panel with a form item for each field of the record.
 * @cfg {string} urlDataDetail the url to request the Record.
 * @class sitools.user.component.simpleViewDataDetail
 * @extends Ext.Panel
 */
sitools.user.component.simpleViewDataDetail = Ext.extend(Ext.Panel, {
//sitools.component.users.simpleViewDataDetail = Ext.extend(Ext.Panel, {

    initComponent : function () {
        this.url = this.urlDataDetail;
        //get the end of the uri and encode it
        var urlSplited = this.url.split('/');
        this.url = "";
        for (var i = 0; i < urlSplited.length; i++) {
            if (i < urlSplited.length - 1) {
                this.url += urlSplited[i] + "/";
            } else {
                this.url += encodeURIComponent(urlSplited[i]);
            }
        }

        
        this.layout = "fit";
        this.autoScroll = true;
        /*
         * var store = new Ext.data.JsonStore({ // store configs autoDestroy:
         * true, url: this.url, // reader configs root:
         * 'record.attributeValues', fields: ['name', 'value'], autoLoad : true
         * 
         * });
         */

        // set the search form
        this.formPanel = new Ext.FormPanel({
            frame : true,
            autoScroll : true,
            labelWidth : 150,
            labelAlign : "top"
        });

        var itemsForm = [];

        Ext.Ajax.request({
            url : this.url,
            method : 'GET',
            scope : this,
            success : function (ret) {
                var data = Ext.decode(ret.responseText);
                if (!data.success) {
                    Ext.Msg.alert(i18n.get('label.information'), "Server error");
                    return false;
                }
                var record = data.record;
                var id = record.id;
                var attributes = record.attributeValues;
                if (attributes !== undefined) {
                    var i;
                    for (i = 0; i < attributes.length; i++) {
                        var name = attributes[i].name;
                        var value = attributes[i].value;
                        var item;
                        if (value !== null && value.length > 100) {

                            item = new Ext.form.TextArea({
                                fieldLabel : name,
                                value : value,
                                anchor : "90%",
                                readOnly : true
                            });
                        } else {
                            item = new Ext.form.TextField({
                                fieldLabel : name,
                                value : value,
                                anchor : "90%",
                                readOnly : true
                            });
                        }

                        itemsForm.push(item);

                    }
                    this.formPanel.add(itemsForm);
                    this.formPanel.doLayout();
                }
            },
            failure : alertFailure
        });

        this.componentType = 'detail';
        this.items = [ this.formPanel ];

        sitools.user.component.simpleViewDataDetail.superclass.initComponent.call(this);
    }, 
    _getSettings : function () {
        return {};
    }
});
/***************************************
* Copyright 2010-2013 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, ID, i18n, document, showResponse, alertFailure*/
Ext.namespace('sitools.component.version');

sitools.component.version.sitoolsVersion = Ext.extend(Ext.Panel, {
    
	layout : 'fit', 
    
    initComponent : function () {
    this.versionUrl = loadUrl.get('APP_URL') + '/version';
        
        var title = new Ext.form.Label({
            html : '<h2>SITools2</h2><br/>' 
        });
        
        var logo = new Ext.form.Label({
            html : '<img src='+loadUrl.get('APP_URL')+'/res/images/logo_02_tailleMoyenne.png>'
        });
        
        
        
        this.credits = new Ext.form.Label({            
        });
        
        var website = new Ext.form.Label({
            html : '<a href="http://www.sitools2.sourceforge.net">sitools2.sourceforge.net</>'
        });
        
        this.versionLabel = new Ext.form.Label({            
        });
        
        this.buildDateLabel = new Ext.form.Label({            
        }); 
        
        var panelVersion = new Ext.Panel({
            title : i18n.get("label.version"),
            layout : 'fit',
            padding : 10
        });
        
        var panelLicence = new Ext.ux.ManagedIFrame.Panel({
            title : i18n.get("label.licence"),
            layout : 'fit',
            defaultSrc : loadUrl.get('APP_URL') + "/res/licences/gpl-3.0.txt"
            
        });
        
        panelVersion.add([logo, title, this.versionLabel, this.buildDateLabel, this.credits, website]);
        
        this.tabs = new Ext.TabPanel({
            activeTab: 0,
            items: [ panelVersion, panelLicence]            
        });
        
        this.items = [this.tabs];
        
            
        this.listeners = {
            scope : this,
            resize : function (window) {
                var size = window.body.getSize();
                this.tabs.setSize(size);
            }
        };
            
        sitools.component.version.sitoolsVersion.superclass.initComponent.call(this);
    },
    
    afterRender : function () {

        sitools.component.version.sitoolsVersion.superclass.afterRender.apply(this, arguments);
        
        Ext.Ajax.request({
                url : this.versionUrl,
                method : 'GET',
                scope : this,
                success : function (ret) {
                    var json = Ext.decode(ret.responseText);
                    if (!json.success) {
                        Ext.Msg.alert(i18n.get('label.warning'), json.message);
                        return false;
                    }
                    var info = json.info;
                    
                    var version = info.version;
                    var buildDate = info.buildDate;
                    var copyright = info.copyright;
                    
                    this.versionLabel.setText("<h3>Version : " + version + "</h3>", false);                    
                    this.buildDateLabel.setText("<h3>Build date : " + buildDate + "</h3>", false);                    
                    this.credits.setText(String.format("<p>{0}</p><br>", copyright), false);
                    //this.doLayout();
                    
                },
                failure : alertFailure
            });
        
        var size = this.ownerCt.body.getSize();
        this.tabs.setSize(size);
        
    }
});

function showVersion () {
	var versionHelp = Ext.getCmp('winVersionId');
    if (!versionHelp) {
        var panelHelp = new sitools.component.version.sitoolsVersion();
        versionHelp = new Ext.Window({
            title : i18n.get('label.version'),            
            id : 'winVersionId', 
            items : [panelHelp], 
            modal : false, 
			width : 700,
			height : 480,
			resizable : false, 
            modal : true,
			buttons : [{
                text : i18n.get('label.close'),
                
                handler : function () {
                    this.ownerCt.ownerCt.close();
                }
            } ]


        });
        

        versionHelp.show();
        
    } else {
        versionHelp.show();
    }
}

