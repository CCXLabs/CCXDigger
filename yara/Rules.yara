
rule importprint_php_sig_334_php_1_txt {
  strings:
    $s1 = "php system($_GET['xxx']); ?" fullword ascii
    $s2 = "php system($_GET['cmd']); ?" fullword ascii
  condition:
    uint16(0) == 0x3f3c and filesize < 1KB and any of them
}

rule d_py {
strings:
  $s1 = "443: b'GET / HTTP/1.0\\r\\nUser-Agent: %s\\r\\nConnection: close\\r\\n\\r\\n\\r\\n' % USER_AGENT.encode()," fullword ascii
  $s2 = "80: b'GET / HTTP/1.0\\r\\nUser-Agent: %s\\r\\nConnection: close\\r\\n\\r\\n\\r\\n' % USER_AGENT.encode()," fullword ascii
  $s3 = "return '+Vulnerable+ Redis without password'" fullword ascii
  $s4 = "pool = [ threading.Thread(target=thread, args=(ports, udp_ports)) for i in range(THREAD_COUNT)]" fullword ascii
  $s5 = "USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari" ascii
  $s6 = "# -*- coding: utf-8 -*- " fullword ascii
  $s7 = "def lib_get_http_info(addr, port, rep):" fullword ascii
  $s8 = "return lib_get_http_info(addr, port, rep)" fullword ascii
  $s9 = "start = bin_addr[:mask] + (32 - mask) * '0'" fullword ascii
  $s10 = "end = bin_addr[:mask] + (32 - mask) * '1'" fullword ascii
  $s11 = "bin_addr = ''.join([ (8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in  addr.split('.')])" fullword ascii
  $s12 = "bin_addrs = [ (32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:] for i in range(int(start, 2), int(end, 2) + 1)]" fullword ascii
  $s13 = "s.send(payload)" fullword ascii
  $s14 = "s.send(payload1)" fullword ascii
  $s15 = "s.send(payload2)" fullword ascii
  $s16 = "b'\\x00\\x00\\x00\\x4a\\xff\\x53\\x4d\\x42\\x25\\x00\\x00\\x00\\x00\\x18\\x01\\x28\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ascii
  $s17 = "b'\\x00\\x00\\x01\\x0a\\xff\\x53\\x4d\\x42\\x73\\x00\\x00\\x00\\x00\\x18\\x07\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ascii
  $s18 = "b'\\x00\\x00\\x00\\x85\\xff\\x53\\x4d\\x42\\x72\\x00\\x00\\x00\\x00\\x18\\x53\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ascii
 condition:
 uint16(0) == 0x2023 and filesize < 40KB and
 ( $s1 or $s2 ) and ( $s11 or $s12 ) and ( $s13 or $s14 or $s15 ) and ( $s16 or $s17 or $s18 ) and
 4 of ( $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10 )
}

rule default_errorEN_logon_0_aspx {
strings:
  $s1 = "script Language=\"c#\" runat=\"server\"" fullword ascii
  $s2 = "GQEbQABAOAiAAAAAIYYkAMGAAIAAAABAB0ACQCQAwEAEQCQAwYAGQCQAwoAKQCQAxAAMQCQAxAAOQCQAxAAQQCQAxAASQCQAxAAUQCQAxAAWQCQAxAAYQCQAxUAaQCQA" ascii
  $s3 = "GU+AFN5c3RlbS5JTwBkYXRhAG1zY29ybGliAGZ1bmMAUmVhZABBZGQAU3lzdGVtLkNvbGxlY3Rpb25zLlNwZWNpYWxpemVkAEdldE1ldGhvZABSZXBsYWNlAENyZWF0Z" ascii
  $s4 = "3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtY" ascii
  $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAsD4AA" ascii
  $s6 = "nVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGdldF9SZWZlcmVuY2VkQXNzZW1ibGllcwBHZXRUeXBlcwBHZXRCeXRlcwBDb21waWxlclBhcmFtZ" ascii
  $s7 = "h0FAgYOBgABEoCFDgUgABKAiQQgAQgOCSACEoCNEkUdDgUgABKAkQUgAB0SUQUAAgIODgUgARJVDgUAARwSUQYgAhwcHRwIt3pcVhk04IkIAQAIAAAAAAAeAQABAFQCF" ascii
  $s8 = "WJ1dGUAQnl0ZQBFbmNvZGluZwBGcm9tQmFzZTY0U3RyaW5nAFRvU3RyaW5nAEdldFN0cmluZwBDb21wdXRlSGFzaAB3dHMuZGxsAEdaaXBTdHJlYW0ATWVtb3J5U3RyZ" ascii
  $s9 = "GwARgBpAGwAZQBuAGEAbQBlAAAAdwB0AHMALgBkAGwAbAAAACgABAABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAdwB0AHMAAAA0AAgAAQBQAHIAbwBkAHUAYwB0A" ascii
  $s10 = "AoTDxYTECtMEQ8REJoTERERbysAAApyzwAAcCgsAAAKLCwREXLZAABwby0AAAoTEhESLBoRESguAAAKExMREhETFG8vAAAKdSAAAAETBxEQF1gTEBEQEQ+OaTKsEQcTF" ascii
  $s11 = "AAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsARMAgAAAQBTAHQAcgBpAG4AZwBGA" ascii
  $s12 = "wwRCREMFhENbxIAAAoRCxEMFhEMjmlvEwAACiUTDRYw4N4MEQssBxELbxQAAArc3gwRCiwHEQpvFAAACtwRCW8VAAAKCt4MEQksBxEJbxQAAArcKBYAAAoLEgFyAQAAc" ascii
  $s13 = "WFtAFN5c3RlbQBIYXNoQWxnb3JpdGhtAFN5c3RlbS5JTy5Db21wcmVzc2lvbgBTeXN0ZW0uUmVmbGVjdGlvbgBTdHJpbmdDb2xsZWN0aW9uAEV4Y2VwdGlvbgBNZXRob" ascii
  $s14 = "E0ATQAtAGQAZAAgAGgAaAABAy0AAQEADUMAUwBoAGEAcgBwAAAVUwB5AHMAdABlAG0ALgBkAGwAbAAAHVMAeQBzAHQAZQBtAC4AVwBlAGIALgBkAGwAbAAAK1MAeQBzA" ascii
  $encmz = "TVqQAAMAAAAEAAAA//8AAL" ascii /* MZ header, base-64 encoded - always appears in this form as it's at the start of the encoded section */
  condition:
    ( uint16(0) == 0x253c and filesize < 70KB and 1 of ($encmz) and 5 of ($s*) ) or all of them
}

rule logon_aspx1 {
strings:
  /* $x* and $s* represent an OWA logon page, while the remainder of the searches are for a base64-encoded executable embedded in it */
  $x1 = "Response.Write(LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogoffChangePasswordMessage));%>" fullword ascii
  $s2 = "Response.Write(LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogoffMessage));" fullword ascii
  $s3 = "span class=\"signinTxt\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogOn)%" fullword ascii
  $s5 = "span><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ShowPassword)%" fullword ascii
  $s6 = "div class=\"signInInputLabel\" id=\"passwordLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.Passwor" ascii
  $s7 = "div class=\"signInInputLabel\" id=\"passwordLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.Passw" fullword ascii
  $s8 = "form action=\"/owa/auth.owa\" method=\"POST\" name=\"logonForm\" ENCTYPE=\"application/x-www-form-urlencoded\" autocomplete=\"o" ascii
  $s9 = "window.document.getElementById(\"passwordText\").placeholder = \"<%=Strings.GetLocalizedString(Strings.IDs.EnterPas" fullword ascii
  $s10 = "window.document.getElementById(\"password\").placeholder = \"<%=Strings.GetLocalizedString(Strings.IDs.EnterPassword) %" fullword ascii
  $s13 = "window.top.postMessage(operation, \"*\");" fullword ascii
  $s14 = "%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.CloseParentheses) + (IsRtl ? \"&#x200F;\" : \"&#x200E;\")%" fullword ascii
  $s15 = "%=(IsRtl ? \"&#x200F;\" : \"&#x200E;\") + LocalizedStrings.GetHtmlEncoded(Strings.IDs.OpenParentheses)%" fullword ascii
  $s16 = "Response.Write(LocalizedStrings.GetHtmlEncoded(Strings.IDs.TimeoutMessage));" fullword ascii
  $s17 = "string.Format(LocalizedStrings.GetHtmlEncoded(Strings.IDs.BasicExplanation), basicExplanationLink); %" fullword ascii
  $s18 = "span id=\"privateLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ThisIsAPrivateComputer)%" fullword ascii
  $s19 = "div class=\"signInExpl\"><%=string.Format(LocalizedStrings.GetHtmlEncoded(Strings.IDs.CookiesDisabledMessage), " fullword ascii
  $s20 = "span id=\"privateLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ThisIsAPrivateComputer)%" fullword ascii
  $encstr1 = "GQEbQABAOAiAAAAAIYYkAMGAAIAAAABAB0ACQCQAwEAEQCQAwYAGQCQAwoAKQCQAxAAMQCQAxAAOQCQAxAAQQCQAxAASQCQAxAAUQCQAxAAWQCQAxAAYQCQAxUAaQCQA" ascii
  $encstr2 = "GU+AFN5c3RlbS5JTwBkYXRhAG1zY29ybGliAGZ1bmMAUmVhZABBZGQAU3lzdGVtLkNvbGxlY3Rpb25zLlNwZWNpYWxpemVkAEdldE1ldGhvZABSZXBsYWNlAENyZWF0Z" ascii
  $encstr3 = "3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtY" ascii
  $encstr4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAsD4AA" ascii
  $encstr5 = "nVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGdldF9SZWZlcmVuY2VkQXNzZW1ibGllcwBHZXRUeXBlcwBHZXRCeXRlcwBDb21waWxlclBhcmFtZ" ascii
  $encstr6 = "h0FAgYOBgABEoCFDgUgABKAiQQgAQgOCSACEoCNEkUdDgUgABKAkQUgAB0SUQUAAgIODgUgARJVDgUAARwSUQYgAhwcHRwIt3pcVhk04IkIAQAIAAAAAAAeAQABAFQCF" ascii
  $encstr7 = "WJ1dGUAQnl0ZQBFbmNvZGluZwBGcm9tQmFzZTY0U3RyaW5nAFRvU3RyaW5nAEdldFN0cmluZwBDb21wdXRlSGFzaAB3dHMuZGxsAEdaaXBTdHJlYW0ATWVtb3J5U3RyZ" ascii
  $encstr8 = "GwARgBpAGwAZQBuAGEAbQBlAAAAdwB0AHMALgBkAGwAbAAAACgABAABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAdwB0AHMAAAA0AAgAAQBQAHIAbwBkAHUAYwB0A" ascii
  $encstr9 = "AoTDxYTECtMEQ8REJoTERERbysAAApyzwAAcCgsAAAKLCwREXLZAABwby0AAAoTEhESLBoRESguAAAKExMREhETFG8vAAAKdSAAAAETBxEQF1gTEBEQEQ+OaTKsEQcTF" ascii
  $encstr10 = "AAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsARMAgAAAQBTAHQAcgBpAG4AZwBGA" ascii
  $encstr11 = "wwRCREMFhENbxIAAAoRCxEMFhEMjmlvEwAACiUTDRYw4N4MEQssBxELbxQAAArc3gwRCiwHEQpvFAAACtwRCW8VAAAKCt4MEQksBxEJbxQAAArcKBYAAAoLEgFyAQAAc" ascii
  $encstr12 = "WFtAFN5c3RlbQBIYXNoQWxnb3JpdGhtAFN5c3RlbS5JTy5Db21wcmVzc2lvbgBTeXN0ZW0uUmVmbGVjdGlvbgBTdHJpbmdDb2xsZWN0aW9uAEV4Y2VwdGlvbgBNZXRob" ascii
  $encstr13 = "E0ATQAtAGQAZAAgAGgAaAABAy0AAQEADUMAUwBoAGEAcgBwAAAVUwB5AHMAdABlAG0ALgBkAGwAbAAAHVMAeQBzAHQAZQBtAC4AVwBlAGIALgBkAGwAbAAAK1MAeQBzA" ascii
  $encmz = "TVqQAAMAAAAEAAAA//8AAL" ascii /* MZ header, base-64 encoded - will not be bit-displaced */
condition:
    uint16(0) == 0x253c and filesize < 70KB and
    1 of ($encmz) and 4 of ($encstr*) and
    1 of ($x*) and 4 of ($s*)
}

rule logon_aspx2 {
strings:
  $s1 = "$iaddr=inet_aton($target) || die(\"Error: $!\\n\");" fullword ascii
  $s2 = "$system= 'echo \"`uname -a`\";echo \"`id`\";/bin/sh';" fullword ascii
  $s3 = "$target=$ARGV[0];" fullword ascii
  $s4 = "$paddr=sockaddr_in($port, $iaddr) || die(\"Error: $!\\n\");" fullword ascii
  $s5 = "$cmd= \"lynx\";" fullword ascii
  $s6 = "$proto=getprotobyname('tcp');" fullword ascii
  $s7 = "socket(SOCKET, PF_INET, SOCK_STREAM, $proto) || die(\"Error: $!\\n\");" fullword ascii
  $s8 = "connect(SOCKET, $paddr) || die(\"Error: $!\\n\");" fullword ascii
  $s9 = "$port=$ARGV[1];" fullword ascii
  $s10 = "system($system);" fullword ascii
  $s11 = "$0=$cmd;" fullword ascii
condition:
  uint16(0) == 0x2123 and filesize < 1KB and
  5 of them
}

rule About_aspx {
meta:
  description = "file About.aspx_0d1578c4ee70601a2e76b2b5e5b7f08b3278f194ea8acf0004f64c3db4e15eab"
  author = "Jens Waring"
  reference = "CyberCX Malware Scanning Rules v1.0"
  date = "2020-07-02"
  hash1 = "0d1578c4ee70601a2e76b2b5e5b7f08b3278f194ea8acf0004f64c3db4e15eab"
strings:
    $s1 = "%= Microsoft.IdentityManagement.CredentialManagement.Portal.Common.CustomizationProvider.Instance.CustomHeaderHtml%" fullword ascii
    $s2 = "asp:HyperLink runat=\"server\" ID=\"HyperlinkPrivacy\" EnableViewState=\"false\" Target=\"_blank\" /" fullword ascii
    $s3 = "string open_gov=System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(\"PD9" fullword ascii
    $s4 = "string email_server=System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(" fullword ascii
    $s5 = "<% if (!String.IsNullOrEmpty(Microsoft.IdentityManagement.CredentialManagement.Portal.Common.CustomizationProvi" fullword ascii
    $s6 = "System.Xml.Xsl.XslCompiledTransform peopletracker = new System.Xml.Xsl.XslCompiledTransform();" fullword ascii
    $s7 = "System.Xml.Xsl.XslCompiledTransform peopletracker = new System.Xml.Xsl.XslCompiledTransf" fullword ascii
    $s8 = "peopletracker.Load(schaffer, System.Xml.Xsl.XsltSettings.TrustedXslt, new System.Xml.XmlUrlResolver());" fullword ascii
    $s9 = "%= Microsoft.IdentityManagement.CredentialManagement.Portal.Common.CustomizationProvider." fullword ascii
    $s10 = "peopletracker.Load(schaffer, System.Xml.Xsl.XsltSettings.TrustedXslt, new System.Xml.Xml" fullword ascii
    $s11 = "meta http-equiv=\"X-UA-Compatible\" content=\"IE=9\" /" fullword ascii
    $s12 = "System.Xml.XmlDocument manilawebsite = new System.Xml.XmlDocument();" fullword ascii
    $s13 = "System.Xml.XmlDocument schaffer = new System.Xml.XmlDocument();" fullword ascii
    $s14 = "asp:Label runat=\"server\" ID=\"LabelDisclosure\" CssClass=\"aboutVersionRowText aboutVersionRowDisclosure\" /" fullword ascii
    $s15 = "!--[if (gt IE 9)|!(IE)]" fullword ascii
    $s16 = "uU2VydmVyO2V2YWwoU3lzdGVtLlRleHQuRW5jb2RpbmcuVVRGOC5HZXRTdHJpbmcoQ29udmVydC5Gcm9tQ" ascii /* base64 encoded string 'eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64S' */
    $s17 = "zdGVtLlRleHQuRW5jb2RpbmcuVVRGOC5HZXRTdHJpbmcoQ29udmVydC5Gcm9tQmFzZTY0U3RyaW5nKFJlcXVlc3QuSXRlbVsnc2hhcnAnXSkpLCd1bnNhZmUnKTtSZXN" ascii
    $s18 = "<% if (!String.IsNullOrEmpty(Microsoft.IdentityManagement.CredentialManagement.Portal.Common.CustomizationProvider.Instance.Cust" ascii
    $s19 = "peopletracker.Transform(manilawebsite, null, new System.IO.MemoryStream());" fullword ascii
condition:
  uint16(0) == 0x253c and filesize < 20KB and
  10 of them
}

rule InitialSrvWrk_aspx {
meta:
  description = "file InitialSrvWrk.aspx_93516613fdaeceeef96cdd15261ade473fd30a4b9ba2721684d3c1190638093e"
  author = "Jens Waring"
  reference = "CyberCX Malware Scanning Rules v1.0"
  date = "2020-07-02"
  hash1 = "93516613fdaeceeef96cdd15261ade473fd30a4b9ba2721684d3c1190638093e"
strings:
    $s1 = "string nypost = \"H4sIAAAAAAAEAO1Ya2gc1xU+d3b1Gltr78rWw5boOMq6smotK0uyotiOJa0kW4lkKVpZTouJPDt7JY09O7OenVWsOk6cHyE4pCT9kYY6gVL" fullword ascii
    $s2 = "using (System.IO.Compression.GZipStream callsign = new System.IO.Compression.GZipStream(net_nanny, System.IO.Compres" fullword ascii
    $s3 = "byte[] apf4 = System.Convert.FromBase64String(nypost);" fullword ascii
    $s4 = "while ((sandymountster = callsign.Read(mediadirectory, 0, mediadirectory.Length)) > 0)"
    $s5 = "Type guider = crystal_reports.GetType(\"WebCache.IE\");    System.Reflection.MethodInfo cashier = guider.GetMethod(\"Entry\");" fullword ascii
    $s6 = "sion.CompressionMode.Decompress))" fullword ascii
    $s7 = "/Ad5TzOIAGAAA\";    System.Reflection.Assembly crystal_reports = Application[\"enca\"] as System.Reflection.Assembly;    " fullword ascii
    $s8 = "using (System.IO.MemoryStream _namespace = new System.IO.MemoryStream())" fullword ascii
    $s9 = "using (System.IO.MemoryStream net_nanny = new System.IO.MemoryStream(apf4))" fullword ascii
    $s10 = "/TeM+PIUzaB71CfzXmJJ6N8LvfbDZ14ajQS0+d1R8FqEROfKc3EfHsIOKXXwcu+wC9lpR7pe9ZtGqy13aWr8TozxN18MdirCRBi5OFxtn1EZLYamTxK8fSBJ7dkbkgFr" ascii
    $s11 = "n.Read(mediadirectory, 0, mediadirectory.Length)) > 0)" fullword ascii
    $s12 = "crystal_reports = System.Reflection.Assembly.Load(apf4);" fullword ascii
    $s13 = "4N5/HmZbCY6LNFjbilbomNBfR5kjUJAM19ZVrpdBq4cfRKnQc6BeAH5NWObmyHx25t15TiPxsgE4CzYK3xEFb1nsG9UJFb4r6eUvBZ4OWwNM2oXeeiqCiL0VnJJcPRuN" ascii
condition:
  uint16(0) == 0x2a2f and filesize < 400KB and
  4 of them
}


rule default_aspx {
   meta:
      description = "file default.resx_1683cf3a44a3989811404a7a5e180d37a6e52540b6afbc23d14848835a59d28c"
      author = "Jens Waring"
      reference = "CyberCX Malware Scanning Rules v1.0"
      date = "2020-07-02"
      hash1 = "1683cf3a44a3989811404a7a5e180d37a6e52540b6afbc23d14848835a59d28c"
   strings:
      $s1 = "value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" fullword ascii
      $s2 = "value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" fullword ascii
      $s3 = "data name=\"x\" mimetype=\"application/x-microsoft.net.object.binary.base64\">"
      $x1 = "k1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg" ascii
      $x2 = "c2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBCeXRlAHZhbHVlAFJlbW92ZQBTeXN0ZW0uVGhyZWFkaW5nAGdldF9Db250" ascii
      $x3 = "cnRlZABSZWFkVG9FbmQAR2V0TWV0aG9kAGxpc3RlbmVyUGFzc3dvcmQAcHdkAENvbXByZXNzaW9uTW9kZQBVcmxEZWNvZGUAQ29tcGFyZUV4Y2hhbmdlAEludm9rZQBJ" ascii
      $x4 = "RGlzcG9zYWJsZQBSdW50aW1lVHlwZUhhbmRsZQBHZXRUeXBlRnJvbUhhbmRsZQBFdmVudFdhaXRIYW5kbGUAQ29tYmluZQBHZXRUeXBlAE1ldGhvZEJhc2UAZ2V0X1Jl" ascii
      $encml1 = "FdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2Vu"
   condition:
      uint16(0) == 0x723c and filesize < 100KB and
      2 of ($s*) and 2 of ($x*) and 1 of ($encml1)
}

rule logon_aspx_super {
   meta:
      description = "from files logon.aspx_45f5f1018b12f1bb5ea6a4360f16075f53e53f2d0250600bb72fa6491c2786cf, logon.aspx_b35370373adafa7195cfd8324bcca67ab30fa77ee3e13c25cba692db9120e191, logon.aspx_85dca1dcfc875b37882f45d013c1a04974f237ba9abaec34f4e8702868125322"
      author = "Jens Waring"
      reference = "CyberCX Malware Scanning Rules v1.0"
      date = "2020-07-02"
      hash1 = "45f5f1018b12f1bb5ea6a4360f16075f53e53f2d0250600bb72fa6491c2786cf"
      hash2 = "b35370373adafa7195cfd8324bcca67ab30fa77ee3e13c25cba692db9120e191"
      hash3 = "85dca1dcfc875b37882f45d013c1a04974f237ba9abaec34f4e8702868125322"
   strings:
      $x1 = "Response.Write(LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogoffChangePasswordMessage));%" fullword ascii
      $x2 = "span class=\"signinTxt\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogOn)%" fullword ascii
      $x3 = "div class=\"signInInputLabel\" id=\"passwordLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.Passw" fullword ascii
      $x4 = "Response.Write(LocalizedStrings.GetHtmlEncoded(Strings.IDs.LogoffMessage));" fullword ascii
      $x5 = "window.document.getElementById(\"passwordText\").placeholder = \"<%=Strings.GetLocalizedString(Strings.IDs.EnterPassword)" fullword ascii
      $s2 = "span id=\"privateLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ThisIsAPrivateComputer)%" fullword ascii
      $s3 = "div class=\"signInExpl\"><%=string.Format(LocalizedStrings.GetHtmlEncoded(Strings.IDs.CookiesDisabledMessage), \"<br" fullword ascii
      $s4 = "span id=\"privateLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ThisIsAPrivateComputer)%" fullword ascii
      $s5 = "span><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.ShowPassword)%" fullword ascii
      $s6 = "%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.CloseParentheses) + (IsRtl ? \"&#x200F;\" : \"&#x200E;\")%>" fullword ascii
      $s7 = "<%=(IsRtl ? \"&#x200F;\" : \"&#x200E;\") + LocalizedStrings.GetHtmlEncoded(Strings.IDs.OpenParentheses)%" fullword ascii
      $s8 = "span class=\"signinTxt\" tabIndex=\"0\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.Retry) %" fullword ascii
      $s9 = "string.Format(LocalizedStrings.GetHtmlEncoded(Strings.IDs.BasicExplanation), basicExplanationLink); %>" fullword ascii
      $s10 = "var a_fLOff = <%= (Reason == LogonReason.Logoff || Reason == LogonReason.ChangePasswordLogoff || Reason == LogonReason.Timeo" fullword ascii
      $s11 = "<%@ Page language=\"c#\" AutoEventWireup=\"false\" Inherits=\"Microsoft.Exchange.HttpProxy.Logon\" %" fullword ascii
      $s12 = "span id=\"lightLabel\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.UseOutlookWebAccessBasicClient) %" fullword ascii
      $s13 = "span id=\"lightLabel\" aria-hidden=\"true\"><%=LocalizedStrings.GetHtmlEncoded(Strings.IDs.UseOutlookWebAccessB" fullword ascii
      $encmz1 = "H4sIAAAAAAAEAO1YXWwcVxU+d3a9tifxJrtO/JPYY" /* Base64 encoding of a Gzipped MZ header for a specific malicious executable */
   condition:
      ( uint16(0) == 0x253c and filesize < 60KB and ( 1 of ($x*) and 1 of ($encmz1) and 4 of ($s*) ) )
}
