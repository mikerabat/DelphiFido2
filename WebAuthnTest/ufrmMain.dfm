object frmWebAuthnTest: TfrmWebAuthnTest
  Left = 0
  Top = 0
  Caption = 'WebAuthnTest'
  ClientHeight = 319
  ClientWidth = 489
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  DesignSize = (
    489
    319)
  PixelsPerInch = 96
  TextHeight = 13
  object btnVersion: TButton
    Left = 8
    Top = 16
    Width = 114
    Height = 25
    Caption = 'Version'
    TabOrder = 0
    OnClick = btnVersionClick
  end
  object memLog: TMemo
    Left = 128
    Top = 18
    Width = 347
    Height = 284
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object btnUserVerifyAvail: TButton
    Left = 8
    Top = 56
    Width = 114
    Height = 25
    Caption = 'Is User Verify Avail'
    TabOrder = 2
    OnClick = btnUserVerifyAvailClick
  end
  object btnCredential: TButton
    Left = 8
    Top = 129
    Width = 114
    Height = 25
    Caption = 'Make Credential'
    TabOrder = 3
    OnClick = btnCredentialClick
  end
  object btnCheckJSON: TButton
    Left = 8
    Top = 160
    Width = 114
    Height = 25
    Caption = 'Check Output'
    TabOrder = 4
    OnClick = btnCheckJSONClick
  end
  object btnAssert: TButton
    Left = 8
    Top = 277
    Width = 114
    Height = 25
    Caption = 'Assert'
    TabOrder = 5
    OnClick = btnAssertClick
  end
end
