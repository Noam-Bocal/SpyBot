YARA�          �       p                  �  �         �      �  f      x   �      �  |         |         |      0  �                                               D                            ����������������������������������������������������   L      X                     �      �                       ��������K                      +                    f     p                    �     �                    �     �                    �     �                -     �ں�ں��        ����������������           �  	     �ں�ں��          �  ��������           �  	     �ں�ں��            ��������           �  	     �ں�ں��            ��������             	     �ں�ں��            ��������             	     �ں�ں��    E      $  ��������             	     �ں�ں��    @      o  ��������           j      ��������������������default EXPL_Exchange_ProxyNotShell_Patterns_CVE_2022_41040_Oct22_1 SCRIPT  description Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information) author Florian Roth (Nextron Systems) score old_rule_name EXPL_Exchange_ProxyNoShell_Patterns_CVE_2022_41040_Oct22_1 reference https://github.com/kljunowsky/CVE-2022-41040-POC date 2022-10-11 modified 2023-03-15 id d2812fcd-0a20-5bbd-a9e1-9cca1ed58aa3 $sr1 $sa1  200  $fp1  444  $fp2  404  $fp2b  401  $fp3 GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId= $fp4 @test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com w              /   ?B   8           /@   ?B   p      �      �           P                  �� �/�a�u�t�o�d�i�s�c�o�v�e�r�/�a�u�t�o�d�i�s�c�o�v�e�r�.�j�s�o�n�                               �  *4   �                               �  *����� & �                               �o�w�e�r�s�h�e�l�l��l�l�e�h�s�r�e�w�o�                               �  *4   �                               �  *����� & �                               �n�o�s�j�.�r�e�v�o�c�s�i�d�o�t�u�a�/�r�e�v�o�c�s�i�d�o�t�u�a�/� �                                                                                                                                  !                  &                                      0  0  '               4
  3  1  5  1      5          2,  12      5.  50      B  @                      G  A*                                                                  V$      V&      b          b  U6  U:  U>  U@                                                                                  v"      v(                      u4  u8  u<  uD                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
   	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   �  ��������                       �  ��������                       �  ��������                       �  ��������                       �  ��������                       �  ��������                       �  ��������                       �  ��������          8   ������������������������          p   ������������������������          �   ������������������������          �   ������������������������            ������������������������3          P  ������������������������                                       (             0                          (      @      H      `      h      �      �      �      �      �      �      �      �      0                
       
      
      
      
   (   
   0   
   8   
   @   
   P   
   X   
   `   
   h   
   x   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
   �   
      
     
     
      
   (  
   0     h      P      X   
   @  
   H  
   P  
   X     �      �      �   
   h  
   p  
   x  
   �     �      �      �   
   �  
   �  
   �  
   �          �         
   �  
   �  
   �  
   �     H     0     8  
   �  
   �  
   �  
   �     �     h     p  
     
     
     
         
            7      @      I      R      [   