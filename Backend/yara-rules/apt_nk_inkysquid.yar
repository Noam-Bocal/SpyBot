YARA�          �       �  .      @  n      �  >         V      �        �  �      *  �         �!         �)      �  �-                                                                                         �     �     �      �                           �     �     �     �                           	     $     �     �                           �  ��������   �     �                             ��������   `     `             ����������������������������������������������������   *      1                     J      V                     �      �                     �      �                     �      �                     -     7                    �     �                   *      1                     J      �                    �      �                     �      �                    �      �                     -     7                    �     ;                   *      1                     �      �                    J      �                    P     U                    �      �                     -     7                    �     �                   *      1                     �      �                    J      /                    P     r                    �      �                     -     7                    �     �                   *                          J                           _     d                    h     p                    �      t                    -                         �     �                   *                          J      5                    _     d                    h     p                    �      h                    -                         �     s                      �ں�ں��    .      �  ��������           �       �ں�ں��             ��������           �       �ں�ں��            ��������             )     �ں�ں��        ����������������           1  	     �ں�ں��          =  ��������           9  	     �ں�ں��          U  ��������           Q  	     �ں�ں��          n  ��������           j  	     �ں�ں��          �  ��������           �  	     �ں�ں��         `  ��������           9  	  	   �ں�ں��         q  ��������           Q  	  
   �ں�ں��         �  ��������           j  	     �ں�ں��         �  ��������           �  	     �ں�ں��         �  ��������           �  K     �ں�ں��       ����������������           �       �ں�ں��         �  ��������           �       �ں�ں��         �  ��������           �  K    �ں�ں��       ����������������           �  K                   ����������������           �  K     �ں�ں��       ����������������           �  K    �ں�ں��           ��������           �  K     �ں�ں��       ����������������           �  K    �ں�ں��       ����������������           �      ��������������������default APT_RUBY_RokRat_Loader InkySquid  author threatintel@volexity.com description Ruby loader seen loading the ROKRAT malware family. date 2021-06-22 hash1 5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2 license See license at https://github.com/volexity/threat-intel/LICENSE.txt reference https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/ id 69d09560-a769-55d3-a442-e37f10453cde $magic1 'https://update.microsoft.com/driverupdate?id= $magic2 sVHZv1mCNYDO0AzI'; $magic3 firoffset..scupd.size $magic4 $s1 clRnbp9GU6oTZsRGZpZ $s2 RmlkZGxlOjpQb2ludGVy $s3 yVGdul2bQpjOlxGZklmR $s4 XZ05WavBlO6UGbkRWaG APT_PY_BlueLight_Loader InkySquid  Python Loader used to execute the BLUELIGHT malware family. 80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120 f8da3e40-c3b0-5b7f-8ece-81874993d8cd "".join(chr(ord( import ctypes  ctypes.CFUNCTYPE(ctypes.c_int) ctypes.memmove $s5 python ended APT_MAL_Win_DecRok InkySquid  2021-06-23 The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload. hash 6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855 dc83843d-fd2a-52f1-82e8-8e36b135a0c5 $v1 $av1 Select * From AntiVirusProduct $av2 root\SecurityCenter2 $funcformat APT_MAL_Win_RokLoad_Loader InkySquid  A shellcode loader used to decrypt and run an embedded executable. 85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904 229dbf3c-1538-5ecd-b5f8-8c9a9c81c515 $bytes00 APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine S2WLAB_TALON_JACK2 Detects Ruby ShellCode XOR routine used by ScarCruft APT group type APT version 0.1 2021-05-20 https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48 c393f2db-8ade-5083-9cec-f62f23056f8b $hex1 $hex2 A��A��D��A��A�� APT_NK_Scarcruft_evolved_ROKRAT Detects RokRAT malware used by ScarCruft APT group 2021-07-09 53cabf41-0154-5372-b667-60d8a7cb9806 $AES_IV_KEY $url_deocde x       ?B          8      p      �           16   ?B   �           P     �                  J      BB   �     �     0     h     �                 A      BB   �          H     �                       ?    �         0      ?B   �     (                 =      ? �@MZd/$   ?B   `     �                 ��a�l�i�a�s� �U�r�l�F�i�l�t�e�r�       �                        �  4   �       �                        �  ����� & �       �                        � �e�v�a�l�;�"��"�;�l�a�v�e� �       �                        �  4   �       �                        �  ����� & �       �                        �r�e�t�l�i�F�l�r�U� �s�a�i�l�a��Ǡ����#�E�g�  �Ǡ�������͢�Ǡ�����ܢ���������ܢ�����Ǣ�͢�������ǵ  �g�E�#�����ǭ�%�0�2�x�  
 �C�r�e�a�t�e�T�h�r�e�a�d��d�a�e�r�h�T�e�t�a�e�r�C�  
 �x�2�0�%��H�����H�����H�����W�A�T�A�U�A�V�A�W�H����������3���蠠���������L����蠠���L����A���֢������D�����蠠���L����蠠���H��H������ࢋ�L����������D�������֢��A�𢋢L������袋�L��������������3����������H�W�A�V�A�U�A�T�A�W�����H�����H�����H����Ǣ�@���Ǣ�t������������t��Ǣ��@��Ǣ���ǢD�$��2�1��#�ǢD�$��4�E�V�g�ǢD�$��x�������ǢD�$�����΢ߢǢE��+�~����ǢE��(���Ң��ǢE���������ǢE��	�ϢO�<��<�O�Ϣ	��E�Ǣ��������E�Ǣ��Ң��(��E�Ǣ���~�+��E�Ǣߢ΢����$�D�Ǣ������x��$�D�Ǣg�V�E�4��$�D�Ǣ#��1�2��$�D�ǭ��������Ȣ��H��H�������ꢃ�H��H���Ȣ񢀢�颀�                                @      B                          *          \              b         p                              #         &         x  �                      #H          3  2,          1<          :    .                         B      �  E
  /X      �   4      �                     3~      /�      < 1�  (�  HP  Y          @ J^          $�      b$  <�      e   .  L     [J  j      Rl  m   .      p  q4  #     t.      ;�      J�      nD  {&      fZ  V�  mN  fj  A�  6 3 7 vV     f�      /> �             tv     d�  �:  3J q�  zd  u�  �r  f�  m�  c�  <B 0P     /H                 u�       X      b  u�      t�          t�      `8                         k     �>  y�  p     iF                         �          �2                          �8                                                              �z                                                      �          ΂                                                                                                                                                                  �|                                                                  ��              ��                      ��                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
                                                                                          	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ������������������������              ������������������������          8   ������������������������          8   ������������������������           p   ������������������������
          p   ������������������������          �      �      �   ��������          �   ������������������������
            ������������������������          P  ������������������������          �  ������������������������          �  ������������������������          �  ������������������������          0  ������������������������          h  ������������������������          �  ������������������������          �     i     �  ��������            ������������������������          H  ������������������������          �     �     �  ��������          �     U     �  ��������          �     �       ��������          (  ������������������������          `          �  ��������          �     �     '  ��������                                       (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
       
      
      
      
   (   
   0   
   8   
   @      h      P      X   
   P   
   X   
   `   
   h   
   x   
   �   
   �   
   �      �      �      �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �      �      �      �   
   �   
   �   
      
             �         
     
      
   (  
   0     H     0     8  
   @  
   H  
   P  
   X     �     h     p  
   h  
   p  
   x  
   �     �     �     �  
   �  
   �  
   �  
   �                       (      B      K      T      ]      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     �     �     �  
   �  
   �  
   �  
   �     (            
   �  
   �  
   �  
   �     `     H     P  
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
   p     �      �      �      �      �      �      �      �      �      �      �     �     �     �                      (     @     H     `     h     �     �          �     �  
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
   �     �     �     �  
   �  
      
     
        �      �      �      �      �      �      �      �      �      �     �     �     �     �     �                      (     @     H     `     h     �     �     �  
      
   (  
   0  
   8          �      �                      �     �     �     �     �     �     �     �                      (     @     H                  
   H  
   P  
   X  
   `     X     @     H  
   p  
   x  
   �  
   �     .     7     (     0     @     8     H     `     h     �     �     �     �     �     �     �     �                      (     �     x     �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     j     s  