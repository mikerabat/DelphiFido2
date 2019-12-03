object frmFido2: TfrmFido2
  Left = 0
  Top = 0
  Caption = 'FIDO 2'
  ClientHeight = 335
  ClientWidth = 625
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object lblHint: TLabel
    Left = 8
    Top = 16
    Width = 335
    Height = 13
    Caption = 
      'Note: You need to run this application as Administrator to find ' +
      'devices'
  end
  object lblUser: TLabel
    Left = 344
    Top = 51
    Width = 48
    Height = 13
    Caption = 'Username'
  end
  object lblDisplayname: TLabel
    Left = 344
    Top = 78
    Width = 60
    Height = 13
    Caption = 'Displayname'
  end
  object btnCheckKey: TButton
    Left = 8
    Top = 48
    Width = 75
    Height = 25
    Caption = 'Check Key'
    TabOrder = 0
    OnClick = btnCheckKeyClick
  end
  object memLog: TMemo
    Left = 97
    Top = 48
    Width = 232
    Height = 257
    TabOrder = 1
  end
  object btnWebAuthVersion: TButton
    Left = 8
    Top = 280
    Width = 75
    Height = 25
    Caption = 'WebAuth Ver'
    TabOrder = 2
    OnClick = btnWebAuthVersionClick
  end
  object btnInfo: TButton
    Left = 8
    Top = 79
    Width = 75
    Height = 25
    Caption = 'Info'
    TabOrder = 3
    OnClick = btnInfoClick
  end
  object btnCreateCred: TButton
    Left = 8
    Top = 182
    Width = 75
    Height = 25
    Caption = 'Create Cred'
    TabOrder = 4
    OnClick = btnCreateCredClick
  end
  object btnSetPin: TButton
    Left = 8
    Top = 110
    Width = 75
    Height = 25
    Caption = 'Set Pin'
    TabOrder = 5
    OnClick = btnSetPinClick
  end
  object edUsername: TEdit
    Left = 424
    Top = 48
    Width = 121
    Height = 21
    TabOrder = 6
    Text = 'test'
  end
  object edDisplayName: TEdit
    Left = 424
    Top = 75
    Width = 121
    Height = 21
    TabOrder = 7
    Text = 'Tester'
  end
  object btnMakeAssert: TButton
    Left = 8
    Top = 213
    Width = 75
    Height = 25
    Caption = 'Assertion'
    TabOrder = 8
    OnClick = btnMakeAssertClick
  end
  object btnReset: TButton
    Left = 8
    Top = 141
    Width = 75
    Height = 25
    Caption = 'Reset'
    TabOrder = 9
    OnClick = btnResetClick
  end
  object btnCredman: TButton
    Left = 344
    Top = 280
    Width = 89
    Height = 25
    Caption = 'Creadman Obj'
    TabOrder = 10
    OnClick = btnCredmanClick
  end
  object btnCreadCredObj: TButton
    Left = 344
    Top = 182
    Width = 89
    Height = 25
    Caption = 'Create Cred obj'
    TabOrder = 11
    OnClick = btnCreadCredObjClick
  end
  object Button2: TButton
    Left = 344
    Top = 110
    Width = 89
    Height = 25
    Caption = 'Key Info'
    TabOrder = 12
    OnClick = Button2Click
  end
  object btnAssertObj: TButton
    Left = 344
    Top = 213
    Width = 89
    Height = 25
    Caption = 'Assert Obj'
    TabOrder = 13
    OnClick = btnAssertObjClick
  end
end
