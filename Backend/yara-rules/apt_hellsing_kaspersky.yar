YARA�          �       �  .      @  n      x  �         �      
        �  �!          �!        �-        �=      �  YJ                            $                ��������                                         ��������   �      H              	             H  ��������   �     �                           �  ��������   �     8                           �  ��������   �     �	                           �  ��������   `     (             ����������������������������������������������������   $      ,                     0      9                     <      C                     ^      h                     v      {                     �      �                     �      �                    $      ,                     0      9                     <      C                     ^      h                     v      {                     �      �                    �      �                   $      ,                     0      9                     <      C                     ^      h                     v      {                     �      _                    �      �                   $      ,                     0      9                     <      C                     ^      h                     v      {                     �      �                    �      �                   $      ,                     0      9                     <      C                     ^      h                     v      {                     �      �                    �                         $      ,                     0      9                     <      C                     ^      h                     v      {                     �      	                    �      9	                	      �ں�ں��          �   ��������           �   	     �ں�ں��          �   ��������           �   	     �ں�ں��            ��������             	     �ں�ں��    
      1  ��������           -  	     �ں�ں��          ?  ��������           <  	     �ں�ں��          T  ��������           Q       �ں�ں��          h  ��������           \       �ں�ں��          �  ��������           �       �ں�ں��          �  ��������           �    	   �ں�ں��          �  ��������           �    
   �ں�ں��          �  ��������           �       �ں�ں��            ��������                  �ں�ں��          E  ��������           9  	     �ں�ں��          _  ��������           \  	     �ں�ں��          s  ��������           p  	     �ں�ں��   8      �  ��������           �  	     �ں�ں��         (  ��������           �        �ں�ں��         ?  ��������           �   	     �ں�ں��   (      T  ��������           P  	     �ں�ں��   |      �  ��������           }  	     �ں�ں��            ��������           �  	     �ں�ں��   ,      '  ��������           #  	     �ں�ں��   {      X  ��������           T       �ں�ں��   '      �  ��������           �       �ں�ں��           ��������              	     �ں�ں��         (  ��������           #  K    �ں�ں��         ?  ��������           :  	     �ں�ں��   %      �  ��������           �   	     �ں�ں��   !      �  ��������           �   	     �ں�ں��         �  ��������           �  	     �ں�ں��           ��������           P  	     �ں�ں��   1      7  ��������           }        �ں�ں��         i  ��������           �  	  !   �ں�ں��   	      �  ��������           �   	  "   �ں�ں��         �  ��������           �   	  #   �ں�ں��         �  ��������           �  	  $   �ں�ں��         	  ��������           P  	  %   �ں�ں��           ��������           }  	  &   �ں�ں��         2  ��������           �  	  '   �ں�ں��         H  ��������           #  	  (   �ں�ں��         [  ��������           T  	  )   �ں�ں��         n  ��������           �  	  *   �ں�ں��         ~  ��������              	  +   �ں�ں��         �  ��������           #  	  ,   �ں�ں��         �  ��������           :  	  -   �ں�ں��         -  ��������           �   	  .   �ں�ں��         >  ��������           �   	  /   �ں�ں��   O      E  ��������           �  	  0   �ں�ں��         �  ��������           P  	  1   �ں�ں��   (      �  ��������           }  	  2   �ں�ں��         �  ��������           �    3   �ں�ں��         ^	  ��������           �     4   �ں�ں��         r	  ��������           �   	  5   �ں�ں��   #      �	  ��������           �  	  6   �ں�ں��   :      �	  ��������           P    7   �ں�ں��         �	  ��������           }  	  8   �ں�ں��   $      �	  ��������           �      ��������������������default apt_hellsing_implantstrings version 1.0 filetype PE author Costin Raiu, Kaspersky Lab copyright Kaspersky Lab date 2015-04-07 description detection for Hellsing implants id 00aa5885-ae79-5d68-8587-13d3e8965630 $a1 the file uploaded failed ! $a2 ping 127.0.0.1 $b1 the file downloaded failed ! $b2 common.asp $c xweber_server.exe $d action= $debugpath1 d:\Hellsing\release\msger\ $debugpath2 d:\hellsing\sys\xrat\ $debugpath3 D:\Hellsing\release\exe\ $debugpath4 d:\hellsing\sys\xkat\ $debugpath5 e:\Hellsing\release\clare $debugpath6 e:\Hellsing\release\irene\ $debugpath7 d:\hellsing\sys\irene\ $e msger_server.dll $f ServiceMain apt_hellsing_installer detection for Hellsing xweber/msger installers 0aca838e-813a-59ee-8a04-7d2f4e854075 $cmd cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f "%s" xweber_install_uac.exe system32\cmd.exe $a4 S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y= $a5 S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg= $a6 7dqm2ODf5N/Y2N/m6+br3dnZpunl44g= $a7 vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw== $a8 vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSINjl2tyI $a9 C:\Windows\System32\sysprep\sysprep.exe $a10 %SystemRoot%\system32\cmd.exe $a11 msger_install.dll $a12  ex.dll  apt_hellsing_proxytool detection for Hellsing proxy testing tool 54454f07-11a9-5456-b489-9a9610e53123 PROXY_INFO: automatic proxy url => %s PROXY_INFO: connection type => %d $a3 PROXY_INFO: proxy server => %s PROXY_INFO: bypass list => %s InternetQueryOption failed with GetLastError() %d D:\Hellsing\release\exe\exe\ apt_hellsing_xkat detection for Hellsing xKat tool c831ce04-8fb2-5790-8aaf-c88b370835ac \Dbgv.sys XKAT_BIN release sys file error. driver_load error.  driver_create error. delete file:%s error. delete file:%s ok. kill pid:%d error. kill pid:%d ok. -pid-delete kill and delete pid:%d error. kill and delete pid:%d ok. apt_hellsing_msgertype2 detection for Hellsing msger type 2 implants 98f151de-c1c2-56c1-8c64-5d1f437e0742 %s\system\%d.txt _msger http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s http://%s/data/%s.1000001000 /lib/common.asp?action=user_upload&file= %02X-%02X-%02X-%02X-%02X-%02X apt_hellsing_irene detection for Hellsing msger irene installer b57d1a10-4e5c-511f-b98c-8ce7d766c227 \Drivers\usbmgr.tmp \Drivers\usbmgr.sys common_loadDriver CreateFile error! common_loadDriver StartService error && GetLastError():%d! irene aPLib v0.43 - the smaller the better �       ? �@MZd/#   BB          8           1#   BB   p      �           1       �   /        1Q   ?B   P     �     �     �     0     h     �          1-      �  /        /   %A � f        �      ? �@MZd/�      H  /u   ?B   �     �     �     (     `     �     �          @     x     �          /   %A � f       n      ? �@MZd/H   ?B   �           X     �     �                /   %A�� f       �      ? �@MZd/~   ?B   8     p     �     �          P     �     �     �     0	     h	     �	          /   %A�� f       n      ? �@MZd/H   ?B   �	     
     H
     �
     �
     �
          /   %A � f       n      ? �@MZd/H   ?B   (     `     �     �          @          /   %A � f       �                                                                    H                              �              �       8          (   (                  &L  )      *<       .  .      0  1  2  /*     0B  &X      8$      
  ;
  2�  3�  1r   8   (   (  6n       
  E.  F&   
   
  BT  5     L     ;t  ;�  P  0 ;�  S  T  EZ  ;�  1 ): ;  (  6@    ]   ;$     `         c4  YN  e6  f(  g  h,  E0 j0      fD  m  n8  fF  p  n>  /^ q@  bJ  f�  7N w  j�  mh  n~  s^  f�  e�   0  U( f�  Z>      
     b        p�      j  0  p�  y�      VV c8 e6  �  t     s 4� ]\  .  � ;r  6   4      jD         ]`  0  8� ]b ]d             &� &�         vL                     sP sX Tv 4�     &�  �  3�    on     s~     �     �      $          *�         /� o�  ,  sz      �             ,�             ,   <     :�      4  2� 8� &�  $                        6      `�     m�         h�     e�     / / `� >�     I�     I� I� I�            `�        t�     h� c�      F                  `�                         X e�         i�     i� i� i�     `�     w�             `                              f                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             Q       O   I           G       K   C   >   @   <       ;   M   F   :   5   4       ,   J               +   *   (   $   /         0                 6   9       7       8                   P       E                  &   .       N          )           %                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ������������������������          8   ������������������������	          p   ����������������
                 �   ������������������������          �   ������������������������            ������������������������          P  ������������������������          P  ������������������������          P  ������������������������          P  ������������������������          �  ����������������
   h            �  ����������������
   @            �  ����������������
               �  ����������������
   �             �  ����������������
   �            �  ����������������
   �            �  ����������������
               �  ����������������
   �            �  ����������������
   X            �  ����������������
   0            �  ����������������
   �            �  ����������������
   �            0  ������������������������          0  ������������������������          0  ������������������������          0  ������������������������          h  ����������������
   p            h  ����������������
   �            h  ����������������
   �            h  ����������������
   �            �  ����������������
   �            �  ����������������
   �            �  ����������������
                �  ����������������
   H            �  ������������������������            ������������������������          H  ����������������
   (             �  ����������������
   �             �  ������������������������          �  ������������������������          (  ������������������������          `  ������������������������          �  ������������������������          �  ������������������������*            ����������������
   �  $          @  ����������������
   �  (          x  ����������������
   P            �  ������������������������          �  ������������������������             ����������������
   �            X  ����������������
   �            �  ����������������
   �            �  ������������������������.             ����������������
   �               ����������������
   �               ����������������
   (               ����������������
                8  ������������������������          p  ������������������������          �  ������������������������          �  ������������������������            ����������������
   `	            P  ������������������������          �  ����������������
   �	            �  ������������������������
          �  ����������������
    
  
          0	  ������������������������          h	  ����������������
   (
            �	  ����������������
   x
            �	  ������������������������          
  ������������������������          H
  ������������������������          �
  ����������������
               �
  ������������������������          �
  ������������������������          (  ������������������������          `  ����������������
   �            �  ������������������������          �  ������������������������8            ������������������������          @  ������������������������          9                             (             0                          (      @      H      `      h      �      �      �      �      �      �      0                
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
     
     
      
   (  
   0  
   @  
   H  
   P  
   X  
   h  
   p  
   x  
   �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
     
     
     
         �     �     �  
   0  
   8  
   @  
   H  
   X  
   `  
   h  
   p  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     (            
   �  
   �  
   �  
   �  
   �  
      
     
     
      
   (  
   0  
   8  
   H  
   P  
   X  
   `     `     H     P  
   p  
   x  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
         �     �     �  
     
     
      
   (  
   8  
   @  
   H  
   P  
   `  
   h  
   p  
   x  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
      
     
     
     
   (  
   0  
   8  
   @          �     �  
   P  
   X  
   `  
   h     @     (     0  
   x  
   �  
   �  
   �           !      ;      D      \      k            �      �      �      �      �      �      �      �      H      P      `      X      h      �      �                       (     @     H     `     h     �     �     �     �     x     `     h  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
      
                     
     
      
   (  
   0     X     @     H  
   @  
   H  
   P  
   X     �     x     �  
   h  
   p  
   x  
   �     �     �     �  
   �  
   �  
   �  
   �           �     �  
   �  
   �  
   �  
   �     8           (  
   �  
   �  
   �  
   �     p     X     `  
     
     
     
         �     �     �  
   0  
   8  
   @  
   H     �     �     �  
   X  
   `  
   h  
   p          %     .     7     @     I     R     [     d     m     v          �      �      �      �      �      �     �     �     �                      (     @     H     `     h     �     �                  
   �  
   �  
   �  
   �     P     8     @  
   �  
   �  
   �  
   �     �     p     x  
   �  
   �  
   �  
   �     �     �     �  
   �  
      
     
        �     �     �  
      
   (  
   0  
   8     0             
   H  
   P  
   X  
   `  
   p  
   x  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     �     �     �     �     �     �     �      �      �      �      �      �     �     �     �     �     �                      (     @     H     `     h     h     P     X  
   �  
   �  
   �  
    	     �     �     �  
   	  
   	  
    	  
   (	     �     �     �  
   8	  
   @	  
   H	  
   P	          �        
   `	  
   h	  
   p	  
   x	     H     0     8  
   �	  
   �	  
   �	  
   �	     �     h     p  
   �	  
   �	  
   �	  
   �	     �     �     �  
   �	  
   �	  
   �	  
   �	     �     �     �  
    
  
   
  
   
  
   
     (	     	     	  
   (
  
   0
  
   8
  
   @
     `	     H	     P	  
   P
  
   X
  
   `
  
   h
     �	     �	     �	  
   x
  
   �
  
   �
  
   �
     �	     �	     �	  
   �
  
   �
  
   �
  
   �
     /     8     A     J     S     \     e     n     w     �     �     �     �      �                      �     �     �     �     �     �     �     �                      (     @     H     
     �	     �	  
   �
  
   �
  
   �
  
   �
     @
     (
     0
  
   �
  
   �
  
      
        x
     `
     h
  
     
      
   (  
   0     �
     �
     �
  
   @  
   H  
   P  
   X     �
     �
     �
  
   h  
   p  
   x  
   �                  
   �  
   �  
   �  
   �     �     �     �     �     �           (     0     @     8     H     `     h     �     �     �     �     �     �     �     �                      (     X     @     H  
   �  
   �  
   �  
   �     �     x     �  
   �  
   �  
   �  
   �     �     �     �  
     
     
     
               �     �  
   0  
   8  
   @  
   H     8           (  
   X  
   `  
   h  
   p     p     X     `  
   �  
   �  
   �  
   �     A     J     S     \     e     n  