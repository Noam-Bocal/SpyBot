YARA�          �       p         �   �      �   ~         �      v        X   d      |	  �         �         �      x   X                                            ��������                         ����������������������������������������������������   8      D                     �      �                     �      �                     *     /                    :     C                    N  ��������K             	      �ں�ں��    	      X  ��������           T  	     �ں�ں��    
      f  ��������           b  )    �ں�ں��        ����������������           q      ��������������������default EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24 description Detects emails that contain signs of a method to exploit CVE-2024-21413 in Microsoft Outlook author X__Junior, Florian Roth reference https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/ date 2024-02-17 modified 2024-02-19 score $a1 Subject:  $a2 Received:  $xr1 W       %A � f/#   BB          8           /   ?B   p                   ��f�i�l�e�:�/�/�/�\�\�    �                           � V4   �    �                           � V����� & �    �                           �.�!�������������	��
��������t�g�Z�I�:�-� ��������������������� x�!k�"`�#S�$J�%?�&0�'#�(�)�*��+��,��-��.��/��0��1��2��3��4v�5i�6\�7O�8B�95�:&�;�<�=� �>� �?� �@� �A� �B� �C� �D� �E� �F� �G{ �Hn �Ia �JT �KG �L8 �M) �N �O �d�o�c�x�	 �t�x�t�	 �p�d�f� �x�l�s�x� �p�p�t�x�	 �o�d�t�	 �e�t�c�	 �j�p�g�	 �p�n�g�	 �g�i�f�	 �b�m�p� �t�i�f�f�	 �s�v�g�	 �m�p�4�	 �a�v�i�	 �m�o�v�	 �w�m�v�	 �f�l�v�	 �m�k�v�	 �m�p�3�	 �w�a�v�	 �a�a�c� �f�l�a�c�	 �o�g�g�	 �w�m�a�	 �e�x�e�	 �m�s�i�	 �b�a�t�	 �c�m�d�	 �p�s�1�	 �z�i�p�	 �r�a�r� �7�z� �t�a�r�g�z�	 �i�s�o�	 �d�l�l�	 �s�y�s�	 �i�n�i�	 �c�f�g�	 �r�e�g� �h�t�m�l�	 �c�s�s� �j�a�v�a� �p�y� �c�	 �c�p�p� �d�b�	 �s�q�l�	 �m�d�b� �a�c�c�d�b� �s�q�l�i�t�e�	 �e�m�l�	 �p�s�t�	 �o�s�t� �m�b�o�x�	 �h�t�m�	 �p�h�p�	 �a�s�p�	 �j�s�p�	 �x�m�l�	 �t�t�f�	 �o�t�f� �w�o�f�f� �w�o�f�f�2�	 �r�t�f�	 �c�h�m�	 �h�t�a� �j�s�	 �l�n�k�	 �v�b�e�	 �v�b�s�	 �w�s�f�	 �x�l�s� �x�l�s�m� �x�l�t�m�	 �x�l�t�	 �d�o�c� �d�o�c�m�	 �d�o�t� �d�o�t�m�!��!� !���������������	��
������t�g�Z�I�:�-� ���������������������x� k�!`�"S�#J�$?�%0�&#�'�(�)��*��+��,��-��.��/��0��1��2��3v�4i�5\�6O�7B�85�9&�:�;�<� �=� �>� �?� �@� �A� �B� �C� �D� �E� �F{ �Gn �Ha �IT �JG �K8 �L) �M �N �x�c�o�d�	 �t�x�t�	 �f�d�p� �x�s�l�x� �x�t�p�p�	 �t�d�o�	 �c�t�e�	 �g�p�j�	 �g�n�p�	 �f�i�g�	 �p�m�b� �f�f�i�t�	 �g�v�s�	 �4�p�m�	 �i�v�a�	 �v�o�m�	 �v�m�w�	 �v�l�f�	 �v�k�m�	 �3�p�m�	 �v�a�w�	 �c�a�a� �c�a�l�f�	 �g�g�o�	 �a�m�w�	 �e�x�e�	 �i�s�m�	 �t�a�b�	 �d�m�c�	 �1�s�p�	 �p�i�z�	 �r�a�r� �z�7� �z�g�r�a�t�	 �o�s�i�	 �l�l�d�	 �s�y�s�	 �i�n�i�	 �g�f�c�	 �g�e�r� �l�m�t�h�	 �s�s�c� �a�v�a�j� �y�p� �c�	 �p�p�c� �b�d�	 �l�q�s�	 �b�d�m� �b�d�c�c�a� �e�t�i�l�q�s�	 �l�m�e�	 �t�s�p�	 �t�s�o� �x�o�b�m�	 �m�t�h�	 �p�h�p�	 �p�s�a�	 �p�s�j�	 �l�m�x�	 �f�t�t�	 �f�t�o� �f�f�o�w� �2�f�f�o�w�	 �f�t�r�	 �m�h�c�	 �a�t�h� �s�j�	 �k�n�l�	 �e�b�v�	 �s�b�v�	 �f�s�w�	 �s�l�x� �m�s�l�x� �m�t�l�x�	 �t�l�x�	 �c�o�d� �m�c�o�d�	 �t�o�d� �m�t�o�d�.�    �                           � V4   �    �                           � V�����O& �    �                           �\�\�/�/�/�:�e�l�i�f�             
           
                                                                                                                                                                                                  0                          ;                  ;  ;                                                                                                                                      f
  f  f  d      e      m                                      w      u                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              ������������������������          8   ������������������������	          p            w	  ��������                                       (             0                          (      @      H      `      h      �      �      �      �      0                
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
   h            !      <   