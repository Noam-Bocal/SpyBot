YARA�          �       0  �      �  V	      0	  �         �      �  @      j  �"          �"        �.        �>      8	  �G                                            ��������                                       )  ��������   �      8                            Z  ��������   `     �                            �  ��������                                    G  ��������   �     �                           +  ��������   �     H                           �  ��������   `     �                             ��������   @     �                           �  ��������   �     �             ����������������������������������������������������         (                           �                     �      �                     �      �                     �      �                          (                           �                     �      �                     �      �                     A     G                    �      �                         u                          �                     �      �                     �      �                     A     �                    �                               u                          �                     �      �                     �      �                     A     �                    �      (                         X                          �                     �      �                     �      �                     A     �                    �      �                         u                          �                     �      �                     �      �                     A     >                    �                               	                          �                     �      �                     �      �                     A     Z	                    �	     �	                    �      �	                         	                          �                     �      �                     �      �                     �                               	                          �                     �      �                     �      �                     �      �                      �ں�ں��          #  ��������             	     �ں�ں��   Z      �  ��������             	     �ں�ں��   M        ��������             	     �ں�ں��   |      1  ��������           -  	     �ں�ں��   !      �  ��������           �  �     �ں�ں��   B      M  ��������           -  	     �ں�ں��   E      �  ��������           �  	     �ں�ں��   :      �  ��������           �  �     �ں�ں��   -        ��������             �  	   �ں�ں��   )        ��������             �  
   �ں�ں��   D      8  ��������             �     �ں�ں��   A      �  ��������           }  �     �ں�ں��   #      �  ��������           �  �     �ں�ں��         �  ��������           �  �     �ں�ں��           ��������             �     �ں�ں��   Y      �  ��������           �  �     �ں�ں��   V        ��������             	     �ں�ں��         ]  ��������           -  �     �ں�ں��   %      y  ��������           �  �     �ں�ں��         �  ��������           �  �     �ں�ں��         �  ��������             �     �ں�ں��   &      �  ��������           �  �     �ں�ں��         
  ��������                  �ں�ں��   )      
  ��������                  �ں�ں��         =
  ��������           }       �ں�ں��         O
  ��������           �  �     �ں�ں��   L      W
  ��������           �  �     �ں�ں��         �
  ��������           -  	     �ں�ں��   %      �
  ��������           �  	     �ں�ں��         �
  ��������           �  	     �ں�ں��         �
  ��������             �     �ں�ں��         B  ��������                   �ں�ں��         N  ��������             �  !   �ں�ں��         Z  ��������           -  �  "   �ں�ں��   
      v  ��������           �  �  #   �ں�ں��         �  ��������             �  $   �ں�ں��         �  ��������             �  %   �ں�ں��         �  ��������           }  �  &   �ں�ں��           ��������           �  �  '   �ں�ں��   #      "  ��������           �  �  (   �ں�ں��   J      F  ��������           -    )   �ں�ں��         �  ��������           �      ��������������������default APT_WebShell_Tiny_1 description Detetcs a tiny webshell involved in the Australian Parliament House network compromise author Florian Roth (Nextron Systems) reference https://twitter.com/cyb3rops/status/1097423665472376832 date 2019-02-18 id e65a8920-0684-5aae-a2b8-079c2beae08a $x1 eval( APT_WebShell_AUS_Tiny_2 hash1 0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5 4746d4ce-628a-59b0-9032-7e0759d96ad3 Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String("[password]"))]; $x2 eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" APT_WebShell_AUS_JScript_3 Detetcs a webshell involved in the Australian Parliament House network compromise 7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d ff7e780b-ccf9-53b6-b741-f04a8cbaf580 $s1 <%@ Page Language="Jscript" validateRequest="false"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String $s2 .Item["[password]"])),"unsafe");} APT_WebShell_AUS_4 83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71 bb5b10d1-3528-5361-92fc-8440c65dcda4 wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd); {return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String( $s3 .Equals('User-Agent', StringComparison.OrdinalIgnoreCase)) $s4 gen.Emit(System.Reflection.Emit.OpCodes.Ret); APT_Script_AUS_4 Detetcs a script involved in the Australian Parliament House network compromise fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057 5cbf2476-5ce8-540d-b87b-e400daf49b43 myMutex = CreateMutex(0, 1, "teX23stNew") mmpath = Environ(appdataPath) & "\" & "Microsoft" & "\" & "mm.accdb" $x3 Dim mmpath As String, newmmpath  As String, appdataPath As String $x4 'MsgBox "myMutex Created" Do noting $x5 appdataPath = "app" & "DatA" $x6 .DoCmd.Close , , acSaveYes APT_WebShell_AUS_5 54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4 59b3f6aa-2d3b-54b4-b543-57bd9d981e87 $a1 function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));} $a2 function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));} var hash=DEC(Request.Item[' Response.Write(ENC(SET_ASS_SUCCESS)); hashtable[hash] = assCode; Response.Write(ss); $s5 var hashtable = Application[CachePtr]; HKTL_LazyCat_LogEraser Detetcs a tool used in the Australian Parliament House network compromise 1c113dce265e4d744245a7c55dadc80199ae972a9e0ecbd0c5ced57067cf755b hash2 510375f8142b3651df67d42c3eff8d2d880987c0e057fc75a5583f36de34bf0e a3d74657-a389-5482-ab26-966e790afd50 LazyCat.dll .local_privilege_escalation.rotten_potato LazyCat.Extension  MEOWof VirtualSite: {0}, Address: {1:X16}, Name: {2}, Handle: {3:X16}, LogPath: {4} LazyCat $e3ff37f2-85d7-4b24-a385-7eeb1f5a9562 local -> remote {0} bytes remote -> local {0} bytes HKTL_PowerKatz_Feb19_1 294d6f6c-dbc8-5431-87a0-64abe582c4ea Powerkatz32 Powerkatz64 GetData: not found taskName GetRes Ex: HKTL_Unknown_Feb19_1 bdcadc4b-8881-5dc7-b203-4e79cbc850ed not a valid timeout format! host can not be empty! not a valid port format! {0} - {1} TTL={2} time={3} ping count is not a correct format! The result is too large,program store to '{0}'.Please download it manully. C:\Windows\temp\ @       ? �@<?d1   ? �@<%d/
   %?(f/                  U      ? �@<?d1   ? �@<%d/   %@ f/$   ?B   8      p                  G      ? �@hed/   %@ f/#   BB   �      �                  Z      ? �@fud/   %@ (f/6   ?B        P     �     �                 _      %@ f/H   ?B   �     0     h     �     �                      u      ? �@fud/   %@ f/Q   ?B   H     �     �     �     (     `     �                 o      ?B   �          @     x     �     �           X     �                 T      ?B   �                /$   ?B   8     p                 �      ?B   �     �          P     �          1Q   ?B   �     �          P     �     �     �                 �        H      \      T          l      d      r      t      n              �          �              �                          #L                 (6  )2          F        /.       @      3      .v                                  >   >  *�          )�  D(   D   D      H      )T     &�  M   N  ;z  *8     Fp      T,  UJ      $   @      3H    E�                      2  c&      b`  f@  1� hB  N�  j:  E�  GD mD  n  o$  fb  q
  bh  s>  9� u  bx  wV  x<  y4  uZ  *� |  |N  e�  F� m�  s~  ;� eB m�  f�  t�  4� P� {�  7� *� o�  b�  n�  p�  bt 1� p�  1�    u( t6 |�  fx b� ]�         ^� ?� ud |X                uh up z` f� b�  2  f�      m� {�     u�        {� p� \�  ( p�       @   *� h� b� d�         )�     n� |� o�     t� *�    #�           m "     (     "     <�     * 9�     0     8     H  @   @           D  `             h          B   �   $                           2  6         /F     E  L      �  D   l  3L     b�  t              5J S                     /P     <N                     )t (x -p     X, -v (� <X X. ~  .                  .      )� /�     Df    <|     <�  �  (   l       B  =�          2       6  z$     \R      6                  .           2          dd                                 hl b�             \�                 pr     |\                                 ~j u�                                             ~�                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             5       4       1   0   7   6           -   ,   *   #   "       !                 :   ;                                             )   (   &                                               9   8             %                
       $   	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  ������������������������              ������������������������          8   ������������������������L          p   ������������������������)          �   ������������������������6          �   ������������������������!            ������������������������B          P  ����������������
   x   "          �  ������������������������	          �  ������������������������-          �  ������������������������          0  ������������������������          h  ������������������������          �  ������������������������          �  ������������������������            ������������������������          H  ������������������������          �  ����������������
   �            �  ������������������������          �  ������������������������%          (  ������������������������
          `  ������������������������	          �  ������������������������&          �  ������������������������          �  ������������������������            ������������������������            ������������������������          @  ����������������
   �            @  ����������������
   �            x  ������������������������          x  ������������������������          �  ������������������������          �  ������������������������          �  ������������������������             ������������������������          X  ������������������������          �  ������������������������          �  ������������������������          �  ������������������������             ������������������������             ����������������
   �            8  ������������������������          8  ������������������������          p  ������������������������          p  ����������������
   �            �  ������������������������          �  ������������������������2          �  ������������������������          �  ������������������������(            ����������������
                 ����������������
   0  ,          P  ������������������������          P  ������������������������          �  ����������������
   �  #          �  ����������������
   �  B          �  ������������������������-          �  ������������������������V          �  ������������������������          �  ������������������������       	   *                             (             0                          (      @      H      `      h      �      �      0                
       
      
      
      
   (   
   0   
   8   
   @      -      H      P      `      X      h      �      �      �      �      �      �                       (     @     H     h      P      X   
   P   
   X   
   `   
   h      �      �      �   
   x   
   �   
   �   
   �      q      z      �      �      �      �      �      `     h     �     �     �     �     �     �     �     �                �      �      �   
   �   
   �   
   �   
   �           �         
   �   
   �   
   �   
   �      �      �      �      �      �      �      �            (     @     H     `     h     �     �     �     �     �     �     H     0     8  
   �   
   �   
      
        �     h     p  
     
      
   (  
   0     �     �     �  
   @  
   H  
   P  
   X     �     �     �  
   h  
   p  
   x  
   �           	               �      �                      �     �                      (     @     H     `     h     �     �     (            
   �  
   �  
   �  
   �     `     H     P  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
     
     
     
              �     �  
   0  
   8  
   @  
   H     @     (     0  
   X  
   `  
   h  
   p     M     V     _     h     q     z     (     0     @     8     H     �     �     �     �     �     �                      (     @     H     x     `     h  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �     �     �     �  
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
   `     �     �     �  
   p  
   x  
   �  
   �     �     �     �     �     �     �     �     `     h     x     p     �     `     h     �     �     �     �     �     �     �     �                      (           �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     8           (  
   �  
   �  
   �  
      
     
     
      
   (     p     X     `  
   8  
   @  
   H  
   P  
   `  
   h  
   p  
   x     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �                  
      
     
     
     
   (  
   0  
   8  
   @     P     8     @  
   P  
   X  
   `  
   h     �     p     x  
   x  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �                )     2     ;     D     M     V     _     �     �     �     �     �     @     H     `     h     �     �     �     �     �     �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
      
        0             
     
      
   (  
   0  
   @  
   H  
   P  
   X     h     P     X  
   h  
   p  
   x  
   �  
   �  
   �  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     �     �     �     �     �     �     �     �     �     �     �                      (     @     H     `     h     �     �     �  
     
     
     
      
   0  
   8  
   @  
   H          �        
   X  
   `  
   h  
   p  
   �  
   �  
   �  
   �     H     0     8  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     �     h     p  
   �  
      
     
     
      
   (  
   0  
   8     �     �     �  
   H  
   P  
   X  
   `  
   p  
   x  
   �  
   �     �     �     �  
   �  
   �  
   �  
   �  
   �  
   �  
   �  
   �     (	     	     	  
   �  
   �  
   �  
    	  
   	  
   	  
    	  
   (	     �     �     �     �     �          !     *     3     <     E     N  