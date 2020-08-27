object frmFido2: TfrmFido2
  Left = 0
  Top = 0
  Caption = 'FIDO 2'
  ClientHeight = 438
  ClientWidth = 758
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 17
  object lblHint: TLabel
    Left = 10
    Top = 21
    Width = 425
    Height = 17
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Caption = 
      'Note: You need to run this application as Administrator to find ' +
      'devices'
  end
  object lblUser: TLabel
    Left = 450
    Top = 67
    Width = 61
    Height = 17
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Caption = 'Username'
  end
  object lblDisplayname: TLabel
    Left = 450
    Top = 102
    Width = 77
    Height = 17
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Caption = 'Displayname'
  end
  object btnCheckKey: TButton
    Left = 10
    Top = 63
    Width = 99
    Height = 32
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Check Key'
    TabOrder = 0
    OnClick = btnCheckKeyClick
  end
  object memLog: TMemo
    Left = 127
    Top = 63
    Width = 303
    Height = 336
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    TabOrder = 1
  end
  object btnWebAuthVersion: TButton
    Left = 10
    Top = 366
    Width = 99
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'WebAuth Ver'
    TabOrder = 2
    OnClick = btnWebAuthVersionClick
  end
  object btnInfo: TButton
    Left = 10
    Top = 103
    Width = 99
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Info'
    TabOrder = 3
    OnClick = btnInfoClick
  end
  object btnCreateCred: TButton
    Left = 10
    Top = 238
    Width = 99
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Create Cred'
    TabOrder = 4
    OnClick = btnCreateCredClick
  end
  object btnSetPin: TButton
    Left = 10
    Top = 144
    Width = 99
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Set Pin'
    TabOrder = 5
    OnClick = btnSetPinClick
  end
  object edUsername: TEdit
    Left = 554
    Top = 63
    Width = 159
    Height = 25
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    TabOrder = 6
    Text = 'test'
  end
  object edDisplayName: TEdit
    Left = 554
    Top = 98
    Width = 159
    Height = 25
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    TabOrder = 7
    Text = 'Tester'
  end
  object btnMakeAssert: TButton
    Left = 10
    Top = 279
    Width = 99
    Height = 32
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Assertion'
    TabOrder = 8
    OnClick = btnMakeAssertClick
  end
  object btnReset: TButton
    Left = 10
    Top = 184
    Width = 99
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Reset'
    TabOrder = 9
    OnClick = btnResetClick
  end
  object btnCredman: TButton
    Left = 450
    Top = 366
    Width = 116
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Creadman Obj'
    TabOrder = 10
    OnClick = btnCredmanClick
  end
  object btnCreadCredObj: TButton
    Left = 450
    Top = 238
    Width = 116
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Create Cred obj'
    TabOrder = 11
    OnClick = btnCreadCredObjClick
  end
  object Button2: TButton
    Left = 450
    Top = 144
    Width = 116
    Height = 33
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Key Info'
    TabOrder = 12
    OnClick = Button2Click
  end
  object btnAssertObj: TButton
    Left = 450
    Top = 279
    Width = 116
    Height = 32
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Caption = 'Assert Obj'
    TabOrder = 13
    OnClick = btnAssertObjClick
  end
end
