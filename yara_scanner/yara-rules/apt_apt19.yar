YARA�          �       �   �      `  �      �  f         ~      �  "      ?  a          a         a         a      �  Y"                                            ��������                                       K  ��������   �      �                             ��������   �     0             ����������������������������������������������������                               K      S                     �      �                     �      �                     8     =                    H     N                    �     �                   `     h                    k     t                    �      z                    8     �                          �                    �     9                   `     h                    k     t                    �      *                    8     �                          Y                    �     �                �      �ں�ں��    I      �  ��������           �  �     �ں�ں��    1      	  ��������             �     �ں�ں��    /      ?  ��������           ;  �     �ں�ں��    %      s  ��������           o  �     �ں�ں��    
      �  ��������           �  �     �ں�ں��    w      �  ��������           �  �     �ں�ں��    "      (  ��������           $       �ں�ں��   r      c  ��������           ^       �ں�ں��   '      �  ��������           �    	   �ں�ں��           ��������             	  
   �ں�ں��         �  ��������           �  	     �ں�ں��           ��������             	     �ں�ں��   &      +  ��������           !  	     �ں�ں��         \  ��������           R  	     �ں�ں��   
      �  ��������           w  	     �ں�ں��         �  ��������           �      ��������������������default Beacon_K5om description Detects Meterpreter Beacon - file K5om.dll license Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE author Florian Roth (Nextron Systems) reference https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html date 2017-06-07 hash1 e3494fd2cc7e9e02cff76841630892e4baed34a3e1ef2b9ae4e2608f9a4d7be9 id 9354d20a-d798-55bf-a735-820f21d4a861 $x1 IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s $x2 powershell -nop -exec bypass -EncodedCommand "%s" $x3 %d is an x86 process (can't inject x64 content) $s1 Could not open process token: %d (%u) $s2 0fd00b.dll $s3 %s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s $s4 Could not connect to pipe (%s): %d FE_LEGALSTRIKE_MACRO version .1 filetype MACRO Ian.Ahl@fireeye.com @TekDefense - modified by Florian Roth 2017-06-02 This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7. eb15e5aa-16e5-5c07-a293-ad15c0c09d8e $ob1 ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101) $wsobj1 Set Obj = CreateObject("WScript.Shell") $wsobj2 Obj.Run  FE_LEGALSTRIKE_RTF joshua.kim@FireEye. - modified by Florian Roth Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom b62ceffa-445f-517e-b86b-56e47876c6c0 $lnkinfo 4c0069006e006b0049006e0066006f $encoded1 4f4c45324c696e6b $encoded2 52006f006f007400200045006e007400720079 $encoded3 4f0062006a0049006e0066006f $encoded4 4f006c0065 $datastore \*\datastore �       ? �@MZd/   %A `	 f/~   ?B          8      p           1Q   ?B          8      p      �      �           P                  8      BB   �     �     �                 b      ? �Atr\{d/G   BB   0     h     �     �          H                 �                              &                      .                                                                     �     #          �         )          +      �  /  0  1  &6  &0  1,  5  6  3   6"          &N  2<  )P  5*  22      1:              4>   ,          2Z  1D  #�     7V  1�      P
  3�  3�  /�        4�     1�  /�             ]  3�          6�      *�  d  :�  #�      c$      *�     ]4      c@          d8                              cT  8�      u(  kH  bt  e�                                  uJ              tr      v�  t�                                                                                                      o�                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
                                      	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ������������������������9          8   ������������������������1          p   ������������������������          �   ������������������������%          �   ������������������������            ������������������������          P  ������������������������          �  ������������������������           �  ������������������������<          �  ������������������������          �  ������������������������,          �  ������������������������          �  ������������������������          0  ������������������������          h  ������������������������          �  ������������������������          �  ������������������������            ������������������������
          H  ������������������������                                       (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
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
        &      /      8      R      [      d      m      v            �      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     �  
     
      
   (  
   0  
   @  
   H  
   P  
   X     �     �     �  
   h  
   p  
   x  
   �  
   �  
   �  
   �  
   �     (            
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     �      �      �      �      �      �      �      �      �     �     �     �     �     �                      (     @     H     `     H     P  
     
     
     
         �     �     �  
   0  
   8  
   @  
   H     �     �     �  
   X  
   `  
   h  
   p          �     �  
   �  
   �  
   �  
   �     @     (     0  
   �  
   �  
   �  
   �     x     `     h  
   �  
   �  
   �  
   �     �      �                     #  