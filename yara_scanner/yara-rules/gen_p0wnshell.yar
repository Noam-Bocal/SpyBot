YARA�          �       0  �      @                   6      c  �'      �  a+          a+        e7        mG      �  UP                                            ��������                                       \     y     �      �                           �  ��������         �                           �  ��������   �     �                           �  ��������   �                                 �  ��������   �     p                           �
  ��������   �     0	                           �  ��������   `     �
                             ��������   @     `             ����������������������������������������������������         #                     k      s                     �      �                     �      �                     #     (                    3     9                    z     }                                             k      s                     �      �                    �      �                     #     (                    �     �                    3     �                      ��������                 z     (                         �                    k      s                     �      �                     �      �                     #     (                    3                          z     a                         �                    k      s                     �      �                     �      �                     #     (                    3     @                    z     �                         �                    �      �                     �      �                     #     (                    �     F                    3     Q                    z     �                         	                    k      s                     �      �                     �      �                     #     (                    3     Z	                    z     �	                         �
                    k      s                     �      �                     �      �                     #     (                    3     �
                    z     !                         �                    k      s                     �      �                     �      �                     #     (                    3     =                    z     ~                         %                    k      s                     �      �                     �      �                     #     (                    �  ��������                 3     �                    z     �                �      �ں�ں��    +      �  ��������           �  �     �ں�ں��          �  ��������           �  �     �ں�ں��          �  ��������           �  �     �ں�ں��          �  ��������           �  �     �ں�ں��            ��������             	     �ں�ں��          '  ��������           #  �     �ں�ں��          @  ��������           <  �     �ں�ں��         M  ��������           �  �     �ں�ں��         f  ��������           �  �  	   �ں�ں��         z  ��������           �  �  
   �ں�ں��         �  ��������           �  �     �ں�ں��         �  ��������             �     �ں�ں��         �  ��������           #  �     �ں�ں��         �  ��������           <  �     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �       �ں�ں��           ��������                   �ں�ں��           ��������             	     �ں�ں��   #      @  ��������           ;  	     �ں�ں��   S      i  ��������           d  	     �ں�ں��   
      �  ��������           �  �     �ں�ں��         �  ��������           �  �     �ں�ں��   #      �  ��������           �  	     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �  �     �ں�ں��         �  ��������             �     �ں�ں��         �  ��������           �  �     �ں�ں��   9      �  ��������           �       �ں�ں��   �      �  ��������           �       �ں�ں��         M  ��������           �  �     �ں�ں��   8      8  ��������           �  �     �ں�ں��   3      q  ��������           �  �      �ں�ں��   C      �  ��������               !   �ں�ں��         �  ��������              �  "   �ں�ں��         �	  ��������           �  �  #   �ں�ں��         �	  ��������             �  $   �ں�ں��         �	  ��������           #  �  %   �ں�ں��         
  ��������           
  �  &   �ں�ں��         $
  ��������            
  �  '   �ں�ں��   "      9
  ��������           5
  �  (   �ں�ں��         a
  ��������           \
  �  )   �ں�ں��         z
  ��������           u
  	  *   �ں�ں��   m      F  ��������           �  	  +   �ں�ں��   l      �  ��������           �  	  ,   �ں�ں��   l      !  ��������           �  	  -   �ں�ں��   i      �  ��������           �  	  .   �ں�ں��   i      �  ��������             	  /   �ں�ں��   i      b  ��������           #  �  0   �ں�ں��         �  ��������           <  �  1   �ں�ں��         '  ��������           �  �  2   �ں�ں��         �  ��������           �  	  3   �ں�ں��   m      �  ��������           �  �  4   �ں�ں��   B      �  ��������           �  �  5   �ں�ں��   2      �  ��������           �  �  6   �ں�ں��   0      2  ��������           .      ��������������������default p0wnedPowerCat description p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs license Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE author Florian Roth (Nextron Systems) reference https://github.com/Cn33liz/p0wnedShell date 2017-01-14 hash1 6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf id 059a8e58-7b7e-582e-ba4a-80e4dffe9b5e $x1 Now if we point Firefox to http://127.0.0.1 $x2 powercat -l -v -p $x3 P0wnedListener $x4 EncodedPayload.bat $x5 powercat -c  $x6 Program.P0wnedPath() $x7 Invoke-PowerShellTcpOneLine Hacktool_Strings_p0wnedShell FILE  Detects strings found in Runspace Post Exploitation Toolkit Florian Roth modified 2023-02-10 e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60 nodeepdive 0846039d-1e00-5224-9560-55ab18034d54 Invoke-TokenManipulation windows/meterpreter lsadump::dcsync p0wnedShellx86 p0wnedShellx64 Invoke_PsExec() Invoke-Mimikatz $x8 Invoke_Shellcode() $x9 Invoke-ReflectivePEInjection $fp1 Sentinel Labs, Inc. $fp2 Copyright Elasticsearch B.V. $fp3 Attack Information: Invoke-Mimikatz $fp4 a30226 || INDICATOR-SHELLCODE Metasploit windows/meterpreter stage transfer attempt $fp5 use strict p0wnedPotato p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b 2c2378e3-b948-5325-9afd-76424a7130b1 Invoke-Tater P0wnedListener.Execute(WPAD_Proxy);  -SpooferIP  TaterCommand() FileName = "cmd.exe", p0wnedExploits p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs 54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b 9f754f5f-85e8-5b6f-bde2-566da4d39586 Pshell.RunPSCommand(Whoami); If succeeded this exploit should popup a System CMD Shell p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe 2021-09-15 d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449 c9791804-4f08-5b7e-8d9d-37e2dfccec47 Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf -CreateProcess "cmd.exe" -Username "nt authority\system" CommandShell with Local Administrator privileges :) Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost  AVSignature p0wnedListenerConsole p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169 77d13c34-3e15-5bc1-a100-f04be38cfb44 Invoke_ReflectivePEInjection p0wnedShell>  Resources.Get_PassHashes $s7 Invoke_CredentialsPhish $s8 Invoke_Shellcode $s9 Resources.Invoke_TokenManipulation $s10 Resources.Port_Scan $s20 Invoke_PowerUp p0wnedBinaries p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7 0c62dd3a-195c-5890-b262-2eb00c58f8c1 Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9 wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98 LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+ XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/ STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR namespace p0wnedShell p0wnedAmsiBypass p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs 345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284 168af265-d3e9-59a2-b754-20d6c9a298b1 H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe p0wnedShell_outputs p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs super_rule c19fc14b-0c42-5dd1-bff2-ba75f4168d9c $s1 [+] For this attack to succeed, you need to have Admin privileges. $s2 [+] This is not a valid hostname, please try again $s3 [+] First return the name of our current domain. �       ? �@usd/   %A X f/Q   ?B          8      p      �      �           P          1Q   ?B          8      p      �      �           P                  �      %A  @f/c   ?B   �     �     �     0     h     �     �          H          /@   ?B   �     �     �     (     `                 K      ?B   �     �          @     x                 /      BB   �     �                 �      ?B         X     �     �                /I   ?B         X     �     �           8                 f      ?B   p     �     �          P     �     �     �                 ]      ?B   0	     h	     �	     �	     
     H
     �
                 9      ?B   �
     �
     (                 9      ?B   `     �     �                 �                            R              Z      z          �          x                       <          �           @          �      6     �   F                          .   0  0@  ,P  2  3  0>  ,X      7          <   J                   "  /|  B  C$       B   B              G:  1�  L  M  8V  4 /�  Q4  2<     1�  I�      8B )j  
          4J #|  6  4h  (  Wl  b6  Tp  d  e0  f<  f2  h  *� j"  /�     m.  nB  o,  pJ  qF  FF qN  t  u  v*  iT  x
  y(  ft  e^  8P ur  f$ bD Y@ pv  d, n�  WZ j�  I` b�      n�  TH j0 Dx t> z~  fL y�  l�   <  p8 jd W�    7�  "  9� Q�      J  x�                 6               <  �     qt o� f� s�     � o�       "  l�         c� q� b� 1�  F  )�          )� f�     *� e�      ,            ,          1� t� /�  <      3� 1� x� 4� 0� 3�     8        9� 4  F      * ,
  6  D    x�         J  
   <   0  -  
      ^  �                 *:      @  /" /$    *<     -* < 36     ;  "                          8          "          j 5> 7@         0N x�     1H .R ;B /V <F                            �       �      t  @  8b    p      ,   ,  j      <                                                                                                                                                  f`     oX             oZ                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         7   6   2       0   /           .       +               $       #   -         1                                           9           8                                         
   !      4   ,       	                    5       &                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ������������������������%          8   ������������������������          p   ������������������������          �   ������������������������          �   ����������������
   (               ������������������������
          P  ������������������������          �  ����������������
   �             �  ������������������������          �  ������������������������          0  ������������������������          h  ������������������������          �  ������������������������          �  ����������������
                 ������������������������          H  ����������������
               �  ������������������������          �  ������������������������          �  ������������������������4          �  ������������������������          (  ������������������������          `  ������������������������          �  ����������������
   X            �  ������������������������#            ������������������������          @  ������������������������          x  ������������������������          �  ������������������������          �  ������������������������             ������������������������N          X  ������������������������
          �  ������������������������          �  ������������������������
             ����������������
   �  
          8  ������������������������          8  ������������������������          p  ����������������
   (  
          �  ������������������������          �  ������������������������            ����������������
   �  
          P  ����������������
     
          �  ����������������
   �            �  ����������������
   h            �  ����������������
   @  
          0	  ������������������������)          h	  ������������������������*          �	  ������������������������W          �	  ������������������������           
  ������������������������'          H
  ������������������������d          �
  ������������������������          �
  ����������������
   �   
          �
  ����������������
   �            (  ������������������������L          `  ������������������������B          �  ������������������������!          �  ������������������������0       	   7                             (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
       
      
      
         h      P      X   
   (   
   0   
   8   
   @      �      �      �   
   P   
   X   
   `   
   h      �      �      �   
   x   
   �   
   �   
   �           �         
   �   
   �   
   �   
   �      H     0     8  
   �   
   �   
   �   
   �      �     h     p  
   �   
   �   
      
        &      /      8      A      J      S      \      w      �      �      �      �      �      �      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     �     �     �     �     �     �     �  
     
      
   (  
   0     �     �     �  
   @  
   H  
   P  
   X     (            
   h  
   p  
   x  
   �     `     H     P  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �          �     �  
     
     
     
         @     (     0  
   0  
   8  
   @  
   H     x     `     h  
   X  
   `  
   h  
   p     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �                  
   �  
      
     
        X     @     H  
      
   (  
   0  
   8     �     x     �  
   H  
   P  
   X  
   `     �      �      �      �                           )     D     M     V     _     h     �      �      �      �      �                       (     @     H     `     h     �     �     �     �     �     �     �     �     �  
   p  
   x  
   �  
   �           �     �  
   �  
   �  
   �  
   �     8           (  
   �  
   �  
   �  
   �     p     X     `  
   �  
   �  
   �  
         �     �     �  
     
     
      
   (     �     �     �     �     �     �      �      �      �      �      �     �                      (     @     H     `     h     �     �     �     �     �     �     �  
   8  
   @  
   H  
   P                  
   `  
   h  
   p  
   x     �     �     �      �                      �     �     �     �                      (     @     H     `     h     �     �     P     8     @  
   �  
   �  
   �  
   �     �     p     x  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
      
     
     
        0             
   (  
   0  
   8  
   @     h     P     X  
   P  
   X  
   `  
   h  
   x  
   �  
   �  
   �                    &     /     I     R     [     d     m     v     (     0     @     8     H     �     �     �     �     �     �                      (     @     H     `     h     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �          �        
   �  
   �  
      
        H     0     8  
     
      
   (  
   0     �     h     p  
   @  
   H  
   P  
   X     �     �     �  
   h  
   p  
   x  
   �     �     �     �  
   �  
   �  
   �  
   �     (	     	     	  
   �  
   �  
   �  
   �     �     �     �     �     �     �     �     �     `     h     x     p     �     �     �     �     �     �     �     �     �                      (     @     H     `	     H	     P	  
   �  
   �  
   �  
   �     �	     �	     �	  
     
     
     
         �	     �	     �	  
   0  
   8  
   @  
   H     
     �	     �	  
   X  
   `  
   h  
   p     @
     (
     0
  
   �  
   �  
   �  
   �     x
     `
     h
  
   �  
   �  
   �  
   �     �
     �
     �
  
   �  
   �  
   �  
   �                          )     2     ;     �     �     �     �     �     `     h     �     �     �     �     �     �     �     �                      (     �
     �
     �
  
   �  
      
     
                     
      
   (  
   0  
   8     X     @     H  
   H  
   P  
   X  
   `     b     k     t     �     �     �     �     �     @     H     `     h     �     �     �     �     �     �     �     �                      (     �     x     �  
   p  
   x  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �           �     �  
   �  
   �  
   �  
   �     �     �     �  