YARA�          �       �   N      �        0  >         V        i      �  
          
                        �  �                                            ��������                                       �  ��������   �      p              ����������������������������������������������������   .      :                     �      �                     �      �                     �      �                     �   ��������K                                           G     J                   .      �                    �      �                     �      �                     �      �                     �   ��������P                       �                    G     7                K     �ں�ں��          t  ��������           o  	     �ں�ں��          �  ��������           �  	     �ں�ں��         `  ��������           \  	     �ں�ں��         p  ��������           �  	     �ں�ں��   
      �  ��������           }  	     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �  	  	   �ں�ں��   -      �  ��������           �      ��������������������default MAL_ELF_ReverseShell_SSLShell_Jun23_1 description Detects reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868) author Florian Roth reference https://www.barracuda.com/company/legal/esg-vulnerability date 2023-06-07 score hash1 8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347 id 91b34eb7-61d2-592e-a444-249da43994ca $sc1  -c /bin/sh  $s1 SSLShell MAL_ELF_SALTWATER_Jun23_1 Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868) 601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80 10a038f6-6096-5d3a-aaf5-db441685102b $x1 libbindshell.so ShellChannel $s2 MyWriteAll $s3 CheckRemoteIp $s4 run_cmd $s5 DownloadByProxyChannel $s6 [-] error: popen failed $s7 /home/product/code/config/ssl_engine_cert.pem W       ? �AFLEd/   ?�?d/   %A  P f/#   BB          8                   N     ? �@Ed/   %A �] f/�   ?B   p           /Z   ?B   p      �      �           P     �     �     �          1Z   ?B   p      �      �           P     �     �     �          1Y   BB   p      �      �           P     �     �     �                 �                                                                                                                                                   2                                      .  0                  !8  /                                                       D
  E                              M  N                      T                              \  T"                              X*          ^(          c&      m  i  i      i$  p  s  f0  f2      `@      v  i6  o.  dB  j<  z          fJ  p:  x,  t4  o>  mF      sD      pH  nL      oN                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          	                                
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             ������������������������          8   ������������������������          p   ������������������������          �   ������������������������          �   ������������������������            ������������������������          P  ������������������������          �  ������������������������          �  ������������������������          �  ������������������������          
                             (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
       
      
      
         h      P      X   
   (   
   0   
   8   
   @      3      <      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     �      �      �   
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
        �     �     �  
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
   �     }      �      �      �      �      �      �      �      �      �      �                          '     0     K     T     ]     f     o     x     �     �  