YARA�          �         �      �  ^      �  V         n      j  �      5                                    h  u                                             ��������                                       �  ��������   �      �                                ��������   �  ��������                           �  ��������   �  ��������           ����������������������������������������������������   !      -                     <      D                     �      �                     �      �                     X     ]                    h     n                    �     �                   !      �                    <      D                     �      �                     �      �                     X     ]                    h     �                                              �     G                   !      �                    <      D                     �      �                     �      �                     X     ]                    h     3                    �     t                   !                          <      D                     �      �                     �      �                     X     ]                    h     3                    �                     �      �ں�ں��    ;      �  ��������           �  	     �ں�ں��    6        ��������             	     �ں�ں��    3      V  ��������           R  �     �ں�ں��         p  ��������           l  �     �ں�ں��         �  ��������           |  �     �ں�ں��   "      �  ��������           �  �     �ں�ں��         �  ��������           �  �     �ں�ں��         �  ��������           �  �     �ں�ں��         �  ��������           �      ��������������������default pe APT_RANCOR_JS_Malware description Rancor Malware license Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE author Florian Roth (Nextron Systems) reference https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/ date 2018-06-26 hash1 1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458 id 83dd9567-199e-511c-8c9a-96422bd793e7 $x1 ,0,0 >%SystemRoot%\system32\spool\drivers\color\fb.vbs",0,0 $x2 CreateObject("Wscript.Shell").Run "explorer.exe ""http $x3 CreateObject("Wscript.Shell").Run "schtasks /create APT_RANCOR_PLAINTEE_Variant Detects PLAINTEE malware 6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31 hash2 bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e f5b68079-0517-504d-a45f-f6ced532db82 $s1 payload.dat $s3 temp_microsoft_test.txt $s4 reg add %s /v %s /t REG_SZ /d "%s" $s6 %s %s,helloworld2 $s9 %s \"%s\",helloworld $s16 recv plugin type %s size:%d APT_RANCOR_PLAINTEE_Malware_Exports c35609822e6239934606a99cb3dbc925f4768f0b0654d6a2adc35eca473c505d fa1e678d-8357-522b-9167-31321ab7753f exports        Add s        Sub        DllEntryPoint number_of_exports APT_RANCOR_DDKONG_Malware_Exports Detects DDKONG malware c94d4ea2-7c16-5003-98ea-253f8a2d01d1        ServiceMain        Rundll32Call )      Q       ? �@<Sd/   %@ f/-   ?B          8      p                   n      ? �@MZd/   %A � f/H   ?B   �      �           P     �     �                 �      ? �@MZd/+            �     �     �  /+            �     �     �  /+            �     �     �  /            �  ?d       �      ? �@MZd/+            �     A     �  /+            �     U     �  /+            �     �     �  /            �  ?d       �                                     
                                                               ,                                #      #  &              &  #                   &$                          &0  -&  #8  *.  4                      32      /<  ;"      />                                                                                          ]                                  f
  f  b                  m  n      p          n  e(  `:  ]@  t              {  i6      q*      t,                      t4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               ������������������������          8   ������������������������          p   ����������������
   (             �   ������������������������          �   ������������������������            ������������������������"          P  ������������������������          �  ������������������������          �  ������������������������          	                                   (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
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
   h      -      6      ?      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     �     �     �      �      �   
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
   X     �      �      �      �      �      �      �      �      �      �      �      �     �                      (     @     H     `     h     �     �     �     �     �      �      �      �      	               $     4     =     F     O     _     h     �      �      �      �      �      �     �     �     �                      (     @     H     `     h     �     �     �     �     �     �     �     �     �     �     �     �     �                 