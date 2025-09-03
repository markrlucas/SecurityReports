let 
    token_uri = "https://login.windows.net/" & #"TenantID" & "/oauth2/token",
    resource="https://api.manage.microsoft.com/",
    tokenResponse = Json.Document(Web.Contents(token_uri,
    [
        Content = Text.ToBinary(Uri.BuildQueryString(
            [
                client_id = #"ClientID",
                resource = resource,
                grant_type = "client_credentials",
                client_secret = #"ClientSecret"
            ]
        )),
        Headers = [Accept = "application/json"], ManualStatusHandling = {400}
    ])),
    access_token = tokenResponse[access_token],
    Kaynak = OData.Feed(#"IntuneWarehouseURL"&"/ReportingService/DataWarehouseFEService/Devices?api-version=beta", [ Authorization = "Bearer " & access_token ], [ ExcludedFromCacheKey = {"Authorization"}, ODataVersion = 4, Implementation = "2.0" ]),
    #"Sorted Rows" = Table.Buffer( 
    Table.Sort(Kaynak,{{"lastSyncDateTime", Order.Descending}})),
    #"removed duplicates1" = Table.Distinct(#"Sorted Rows", {"deviceName"}),
    #"Changed Type" = Table.TransformColumnTypes(#"removed duplicates1",{{"encryptionState", type logical}}),
    #"Replaced Value" = Table.ReplaceValue(#"Changed Type","",null,Replacer.ReplaceValue,{"serialNumber"}),
    #"Filtered Rows" = Table.SelectRows(#"Replaced Value", each ([isDeleted] = false)),
    #"Filtered Rows1" = Table.SelectRows(#"Filtered Rows", each not Text.Contains([deviceName], "NO_SERIAL")),
    #"Removed Duplicates" = Table.Distinct(#"Filtered Rows1", {"serialNumber"}),
    #"Filtered Rows2" = Table.SelectRows(
        #"Removed Duplicates",
        each [serialNumber] <> null and Text.Trim(Text.From([serialNumber])) <> "" and Text.Trim(Text.From([serialNumber])) <> "0"
    )
in
    #"Filtered Rows2"