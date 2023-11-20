function solidity_generate() {
    document.getElementById("start_button_1").innerHTML = "<strong>Generating</strong>";
    var selectedOption = document.getElementById("solidity_name");

    // if (selectedOption.value != null) {
    //     if (selectedOption.value == "ECDSA") {
    //         document.getElementById("solidity_name").value = "ECDSA";
    //         editor1.setValue("// SPDX-License-Identifier: GPL-3.0-or-later\npragma solidity ^0.8.20;\nimport { ERC20 } from \"./ERC20.sol\" ;\nlibrary ECDSA {\n    enum RecoverError {\n       NoError,\n      InvalidSignature,\n      InvalidSignatureLength,\n      InvalidSignatureS\n    }\n    error ECDSAInvalidSignature();\n    error ECDSAInvalidSignatureLength(uint256 length);\n    error ECDSAInvalidSignatureS(bytes32 s);\n\r    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError, bytes32) {\n        if (signature.length == 65) {\n            bytes32 r;\n            bytes32 s;\n            uint8 v;\n            assembly {\n                r := mload(add(signature, 0x20))\n                s := mload(add(signature, 0x40))\n                v := byte(0, mload(add(signature, 0x60)))\n         }\n         return tryRecover(hash, v, r, s);\n     } else {\n          return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));\n      {\n    }\n\r    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {\n        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);\n        _throwError(error, errorArg);\n        return recovered;\n    }\n}\n\r    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError, bytes32) {\n        unchecked {\n            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);\n\r            uint8 v = uint8((uint256(vs) >> 255) + 27);\n            return tryRecover(hash, v, r, s);\n        }\n    }\n\r    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {\n        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);\n        _throwError(error, errorArg);\n        return recovered;\n    }\n\r    function tryRecover(\n        bytes32 hash,\n        uint8 v,\n        bytes32 r,\n        bytes32 s\n    ) internal pure returns (address, RecoverError, bytes32) {\n        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {\n            return (address(0), RecoverError.InvalidSignatureS, s);\n        }\n\r        address signer = ecrecover(hash, v, r, s);\n        if (signer == address(0)) {\n            return (address(0), RecoverError.InvalidSignature, bytes32(0));\n        }\n\r        return (signer, RecoverError.NoError, bytes32(0));\n    }\n\r    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {\n        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);\n        _throwError(error, errorArg);\n        return recovered;\n    }\n\r    function _throwError(RecoverError error, bytes32 errorArg) private pure {\n        if (error == RecoverError.NoError) {\n            return; // no error: do nothing\n        } else if (error == RecoverError.InvalidSignature) {\n            revert ECDSAInvalidSignature();\n        } else if (error == RecoverError.InvalidSignatureLength) {\n            revert ECDSAInvalidSignatureLength(uint256(errorArg));\n        } else if (error == RecoverError.InvalidSignatureS) {\n            revert ECDSAInvalidSignatureS(errorArg);\n        }\n    }\n}\ncontract ERC20Permit is ERC20 {\n    using ECDSA for bytes32;\n    mapping(address => uint256) public nonces;\n    bytes32 public constant TYPEHASH = keccak256(\"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)\");\n    bytes32 public DOMAIN_SEPARATOR = keccak256(abi.encode(keccak256(\"EIP712Domain(uint256 chainId,address verifyingContract)\"),block.chainid,address(this)));\n    function permit (address _owner,address _spender,uint256 _value,uint256 deadline,uint8 v,bytes32 r,bytes32 s) public\n    {\n        require(deadline>=block.timestamp,\"Expired deadline!\");\n        bytes32 hash = keccak256(abi.encodePacked('\x19\x01',DOMAIN_SEPARATOR,keccak256(abi.encodePacked(TYPEHASH, _owner, _spender, _value, nonces[_owner]++, deadline))));\n        require(ECDSA.recover(hash, v, r, s) != address(0) && ECDSA.recover(hash, v, r, s) == _owner, \"Invalid Signature!\");\n        _approve(_owner,_spender,_value);\n    }\n}");
    //     } else if (selectedOption.value == "Merkle") {
    //         document.getElementById("solidity_name").value = "Merkle";
    //         editor1.setValue("pragma solidity ^0.8.18;\ncontract Search {\n	bytes32 public rootHash;\n	constructor(bytes32 _rootHash) {\n		rootHash = _rootHash;\n	}\n	function search (bytes32 _leaf,bytes32[] memory proof) public view\n	{\n		bytes32 computedHash = keccak256(abi.encodePacked(_leaf));\n		for(uint256 i = 0; i < proof.length; i++){\n			if(computedHash < proof[i]){\n				computedHash = sha256(abi.encodePacked(computedHash, proof[i]));\n			}\n			else{\n				computedHash = sha256(abi.encodePacked(proof[i], computedHash));\n			}\n		}\n		require(rootHash == computedHash, \"Invalid Commit!\");\n	}\n");

    //     } else if (selectedOption.value == "Pederson") {
    //         document.getElementById("solidity_name").value = "Pederson";
    //         editor1.setValue("// SPDX-License-Identifier: GPL-3.0-or-later\nimport { Counting } from \"./Counting.sol\" ;\nlibrary Pedersen {\n    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 result) {\n        assembly {\n            let memPtr := mload(0x40)\n            mstore(memPtr, 0x20)\n            mstore(add(memPtr, 0x20), 0x20)\n            mstore(add(memPtr, 0x40), 0x20)\n            mstore(add(memPtr, 0x60), base)\n            mstore(add(memPtr, 0x80), exponent)\n            mstore(add(memPtr, 0xa0), modulus)\n\r            let success := staticcall(gas(), 0x05, memPtr, 0xc0, memPtr, 0x20)\n            switch success\n            case 0 {\n                revert(0x0, 0x0)\n            } default {\n                result := mload(memPtr)\n            }\n        }\n    }\n}\ncontract Vote is Counting {\n	using Pedersen for uint256;\n	mapping(address => uint256) public commit;\n	function commitTo(uint256 _commitment) public {\n		commit[msg.sender] = _commitment;\n	}\n	function revealVote (uint256 _value,uint256 randomness) public\n	{\n		uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;\n		uint256 g = 7;\n		uint256 h = uint256(sha256(abi.encodePacked(randomness)));\n		uint256 c = mulmod(Pedersen.modExp(g,_value, q),Pedersen.modExp(h, randomness, q),q);\n		require(commit[msg.sender] == c, \"Invalid Commit!\");\n		_count(_value);\n	}\n}");

    //     } else if (selectedOption.value == "RSA") {
    //         document.getElementById("solidity_name").value = "RSA";
    //         editor1.setValue("// SPDX-License-Identifier: GPL-3.0-or-later\npragma solidity ^0.8.18;\nlibrary RsaVerify {\n    /** @dev Verifies a PKCSv1.5 SHA256 signature\n      * @param _sha256 is the sha256 of the data\n      * @param _s is the signature\n      * @param _e is the exponent\n      * @param _m is the modulus\n      * @return true if success, false otherwise\n    */    \n    function pkcs1Sha256(\n        bytes32 _sha256,\n        bytes memory _s, bytes memory _e, bytes memory _m\n    ) public view returns (bool) {\n        \n        uint8[17] memory sha256ExplicitNullParam = [\n            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00\n        ];\n        uint8[15] memory sha256ImplicitNullParam = [\n            0x30,0x2f,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01\n        ];\n        \n        // decipher\n        bytes memory input = bytes.concat(\n            bytes32(_s.length),\n            bytes32(_e.length),\n            bytes32(_m.length),\n            _s,_e,_m\n        );\n        uint inputlen = input.length;\n        uint decipherlen = _m.length;\n        bytes memory decipher = new bytes(decipherlen);\n        assembly {\n            pop(staticcall(sub(gas(), 2000), 5, add(input,0x20), inputlen, add(decipher,0x20), decipherlen))\n	    }\n        // Check that is well encoded:\n        //\n        // 0x00 || 0x01 || PS || 0x00 || DigestInfo\n        // PS is padding filled with 0xff\n        // DigestInfo ::= SEQUENCE {\n        //    digestAlgorithm AlgorithmIdentifier,\n        //      [optional algorithm parameters]\n        //    digest OCTET STRING\n        // }\n        bool hasNullParam;\n        uint digestAlgoWithParamLen;\n        if (uint8(decipher[decipherlen-50])==0x31) {\n            hasNullParam = true;\n             digestAlgoWithParamLen = sha256ExplicitNullParam.length;\n        } else if  (uint8(decipher[decipherlen-48])==0x2f) {\n            hasNullParam = false;\n            digestAlgoWithParamLen = sha256ImplicitNullParam.length;\n        } else {\n            return false;\n        }\n        uint paddingLen = decipherlen - 5 - digestAlgoWithParamLen -  32 ;\n        if (decipher[0] != 0 || decipher[1] != 0x01) {\n            return false;\n        }\n        for (uint i = 2;i<2+paddingLen;i++) {\n            if (decipher[i] != 0xff) {\n                return false;\n            }\n        }\n        if (decipher[2+paddingLen] != 0) {\n            return false;\n        }\n        // check digest algorithm\n        if (digestAlgoWithParamLen == sha256ExplicitNullParam.length) {\n            for (uint i = 0;i<digestAlgoWithParamLen;i++) {\n                if (decipher[3+paddingLen+i]!=bytes1(sha256ExplicitNullParam[i])) {\n                    return false;\n                }\n            }\n        } else {\n            for (uint i = 0;i<digestAlgoWithParamLen;i++) {\n                if (decipher[3+paddingLen+i]!=bytes1(sha256ImplicitNullParam[i])) {\n                    return false;\n                }\n            }\n        }\n        // check digest\n        if (decipher[3+paddingLen+digestAlgoWithParamLen] != 0x04\n            || decipher[4+paddingLen+digestAlgoWithParamLen] != 0x20) {\n            return false;\n        }\n        for (uint i = 0;i<_sha256.length;i++) {\n            if (decipher[5+paddingLen+digestAlgoWithParamLen+i]!=_sha256[i]) {\n                return false;\n            }\n        }\n        return true;\n    }\n    /** @dev Verifies a PKCSv1.5 SHA256 signature\n      * @param _data to verify\n      * @param _s is the signature\n      * @param _e is the exponent\n      * @param _m is the modulus\n      * @return 0 if success, >0 otherwise\n    */    \n    function pkcs1Sha256Raw(\n        bytes memory _data, \n        bytes memory _s, bytes memory _e, bytes memory _m\n    ) public view returns (bool) {\n        return pkcs1Sha256(sha256(_data),_s,_e,_m);\n    }\n}\ncontract Verify {\n	using RsaVerify for *;\n	mapping(address => uint256) public nonce;\n	function verify (address _owner,address _spender,bytes memory signature, bytes memory exponent, bytes memory module) public\n	{\n		bytes32 hash = sha256(abi.encodePacked(_owner, _spender, block.chainid, address(this), nonce[_owner]));\n		require(RsaVerify.pkcs1Sha256(hash, signature, exponent, module), \"Invalid Signature!\");\n		nonce[_owner]++;\n	}\n}\n");
    //     }
    // }
}
function analyze_solidity() {
    document.getElementById("start_button_1").innerHTML = "<strong>FirstStep</strong>";
    // var type = document.getElementsByClassName("lang_selected")[0].innerHTML;
    // var test_type;
    // if ("function_verify" == document.getElementsByClassName("service_selected").item(0).id) {
    //     test_type = "function_verify";
    // } else {
    //     test_type = "known_debug";
    // }
    var name = document.getElementById("solidity_name").value;
    var code = editor.getValue();
    httpPost(name, code);
    document.getElementById("start_button_1").innerHTML = "<strong>Generating</strong>";
}


function hasClass(elements, cName) {
    return !!elements.className.match(new RegExp("(\\s|^)" + cName + "(\\s|$)")); // ( \\s|^ ) 判断前面是否有空格 （\\s | $ ）判断后面是否有空格 两个感叹号为转换为布尔值 以方便做判断
}
function removeClass(elements, cName) {
    if (hasClass(elements, cName)) {
        elements.className = elements.className.replace(new RegExp("(\\s|^)" + cName + "(\\s|$)"), " "); // replace方法是替换
    }
}

// function analyze_bytecode() {
//     document.getElementById("start_button_2").innerHTML = "<strong>Analyzing</strong>";
//     var type = "bytecode";
//     var name = "";
//     var target = document.getElementById("target_depth").value;
//     var owner = document.getElementById("owner_depth").value;
//     var code = document.getElementById("bytecode").value;
//     httpPost(type, name, code, target, owner);
// }

function httpPost(name, code) {
    var xmlhttp;
    xmlhttp = null;
    if (window.XMLHttpRequest) {
        // code for all new browsers
        xmlhttp = new XMLHttpRequest();
    }
    else if (window.ActiveXObject) {
        // code for IE5 and IE6
        xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
    }
    if (xmlhttp != null) {
	//document.getElementById("start_button_1").innerHTML="<strong>post open</strong>";
        xmlhttp.onreadystatechange = state_Change;
        xmlhttp.open("post", "http://10.0.2.130:8080/api/analyze", true);
	//document.getElementById("start_button_1").innerHTML="<strong>opened</strong>";
        //xmlhttp.setRequestHeader("Content-type", "application/json"); 
        //var content = "type="+type+"&code="+code+"&input="+input;
        var formData = new FormData();
        // formData.append("type", type);
        // formData.append("test_type", test_type)
        formData.append("name", name);
        formData.append("code", code);
        xmlhttp.send(formData);
	//document.getElementById("start_button_1").innerHTML="<strong>sent</strong>";
    }
    else {
        alert("Your browser does not support XMLHTTP.");
    }


    function state_Change() {
        document.getElementById("start_button_1").innerHTML = "<strong>Gernerate Code</strong>";
        //document.getElementById("start_button_2").innerHTML="<strong>Click HERE to Start Analyzing!</strong>";
        if (xmlhttp.readyState == 4) {
            // 4 = "loaded"
            if (xmlhttp.status == 200) {
                // 200 = OK
                //alert(xmlhttp.responseText);
               // document.getElementById("contain").style.display = 'inline';
                var result = xmlhttp.responseText;
                result = JSON.parse(result);
                var o = eval("(" + result + ")");
                code_result = o.code;
		//alert(code_result);
                editor1.setValue(code_result);
                // type = o.type;
                // verif_results = o.result;
                // verif_infos = o.info;
                // linenums = o.linenumber;

                // var errLine;
                // var detect_go = false;
                // unhighlightError();

                // if (type == "verify") {
                //     var newdiv = document.getElementById("newDiv");
                //     if (newdiv != null) {
                //         document.getElementById("newDiv").innerHTML = "";
                //     }

                //     if (detect_go == true) {
                //         var newDiv = document.getElementById("newDiv");
                //         newDiv.style.visibility = 'hidden';
                //     }

                //     if (verif_results[0] == "Error") {
                //         document.getElementById("verify").innerHTML = "验证未通过";
                //         var result_show = "<p class='penal-item'>" + verif_infos[0].replace(/[\n\r]/g, '<br>') + "</p>";
                //         document.getElementById("collapse1").innerHTML = result_show;
                //         //var num2 = reentrancy_info.replace(/[^\d]/g, '');
                //         //var num2 = (/\d+/g).exec(reentrancy_info)
                //         var errLine = linenums[0];
                //         highlightError(errLine - 1);
                //     } else {
                //         document.getElementById("verify").innerHTML = "代码通过";
                //         document.getElementById("collapse1").innerHTML = "";
                //     }
                // }
                // else if (type == "detect_go") {

                //     var newdiv_2 = document.getElementById("newDiv");
                //     if (newdiv_2 != null) {
                //         document.getElementById("newDiv").innerHTML = "";
                //     }

                //     if (verif_results[0].indexOf("Error") != -1) {
                //         document.getElementById("verify").innerHTML = "发现漏洞";
                //         var result_show = "<p class='penal-item'>" + verif_infos[0].replace(/[\n\r]/g, '<br>') + "</p>";
                //         document.getElementById("collapse1").innerHTML = result_show;
                //         //var num2 = reentrancy_info.replace(/[^\d]/g, '');
                //         //var num2 = (/\d+/g).exec(reentrancy_info)
                //         var errLine2 = linenums[0];
                //         highlightError(errLine2 - 1);
                //     } else {
                //         document.getElementById("verify").innerHTML = "代码通过";
                //         document.getElementById("collapse1").innerHTML = "";
                //     }
                // } else if (type == "detect_solidity") {
                //     var newdiv_3 = document.getElementById("newDiv");
                //     if (newdiv_3 != null) {
                //         document.getElementById("newDiv").innerHTML = "";
                //     }

                //     var d = "<div id=\"newDiv\"></div>";
                //     document.getElementById("accordion").innerHTML += d;
                //     // document.getElementById("newDiv").innerHTML = "";

                //     verif_results.forEach((elem, index) => {
                //         if (index == 0) {
                //             document.getElementById("verify").innerHTML = "漏洞名称：" + elem;
                //             var result_show = "<p class='penal-item'>" + "错误信息：" + verif_infos[0].replace(/[\n\r]/g, '<br>') + "</p>";
                //             document.getElementById("collapse1").innerHTML = result_show;
                //         } else {
                //             detect_go = true;

                //             var div = "<div class=\"panel panel-default expanded\">"
                //             var div1 = "<div class=\"panel-heading\" data-toggle=\"collapse\" href=\"#collapse1\">\r\n  <h4 class=\"panel-title expand\">\r\n       <h4 class=\"panel-title expand\">      <div class=\"right-allow pull right\"></div>" + "<span>" + "漏洞名称：" + elem + "</span></h4></div>";
                //             var div2 = "<div class=\"panel-collapse collapse in\" aria-expanded=\"true\">\r\n<p class=\"penal-item\">" + "错误信息：" + verif_infos[index].replace(/[\n\r]/g, '<br>') + "<br></p></div>"
                //             var result_show = div + div1 + div2 + "</div";
                //             document.getElementById("newDiv").innerHTML += result_show;
                //         }
                //         linenums[index].forEach((num, _) => {
                //             highlightError(num - 1);
                //         });


                //     });
                // }


                /*
                if (verif_results[0].indexOf("Error")!=-1) {
                     document.getElementById("verify").innerHTML= "发现错误";
                     var result_show="<p class='penal-item description'>"+verif_infos[0].replace(/[\n\r]/g,'<br>')+"</p>";
                     document.getElementById("collapse1").innerHTML=result_show;
                     //var num2 = reentrancy_info.replace(/[^\d]/g, '');
                     //var num2 = (/\d+/g).exec(reentrancy_info)
                     var errLine = linenums[0]
                     highlightError(errLine-1);
                } else {
                     document.getElementById("verify").innerHTML= "代码通过";
                     document.getElementById("collapse1").innerHTML="";
                }*/
                // var stamp = document.getElementById("contain");
                // removeClass(stamp, "hidden");
            }
            else {
                alert("Problem retrieving XML data");
            }
        }

    }
}


