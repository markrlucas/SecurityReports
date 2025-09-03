let
    // Function to fetch one page of 800 rows, with a 1-second delay
    GetPage = (skip as number) as table =>
        let
            url = "https://api.security.microsoft.com/api/machines?$top=800&$skip=" & Number.ToText(skip),
            delayedFetch = Function.InvokeAfter(
                () => try OData.Feed(url, null, [Implementation="2.0", MoreColumns=true]) otherwise #table({}, {}),
                #duration(0, 0, 0, 1)   // 1 second delay
            )
        in
            delayedFetch,

    // Generate pages until we get an empty table
    PageSkips = List.Generate(
        () => [Skip = 0, Data = GetPage(0)],                     // initial state
        each Table.RowCount([Data]) > 0,                         // keep going while table not empty
        each [Skip = [Skip] + 800, Data = GetPage([Skip])],      // next page
        each [Data]                                              // output only the data
    ),

    // Combine all pages
    Combined = Table.Combine(PageSkips),

    // Add custom column
    AddOnboardedDate = Table.AddColumn(Combined, "OnboardedDate", each try [firstSeen] otherwise null),

    // Change type safely
    ChangeType = Table.TransformColumnTypes(AddOnboardedDate, {{"OnboardedDate", type date}}),

    // Safe computerDnsName extraction
    ExtractedText = if Table.HasColumns(ChangeType, "computerDnsName") 
                    then Table.TransformColumns(ChangeType, {{"computerDnsName", each Text.BeforeDelimiter(_, "."), type text}})
                    else ChangeType,

    // Expand recommendations only if it exists
    ExpandedRecs = if Table.HasColumns(ExtractedText, "recommendations") 
                   then Table.ExpandTableColumn(
                        ExtractedText,
                        "recommendations",
                        {"id", "productName", "recommendationName", "weaknesses", "vendor", "recommendedVersion",
                         "recommendedVendor", "recommendedProgram", "recommendationCategory", "subCategory",
                         "severityScore", "publicExploit", "activeAlert", "associatedThreats", "remediationType",
                         "status", "configScoreImpact", "exposureImpact", "totalMachineCount", "exposedMachinesCount",
                         "nonProductivityImpactedAssets", "relatedComponent", "hasUnpatchableCve", "tags",
                         "exposedCriticalDevices", "software", "vulnerabilities", "Vulnerabilities", "Software",
                         "MachineReferences"},
                        {"recommendations.id", "recommendations.productName", "recommendations.recommendationName", "recommendations.weaknesses",
                         "recommendations.vendor", "recommendations.recommendedVersion", "recommendations.recommendedVendor",
                         "recommendations.recommendedProgram", "recommendations.recommendationCategory", "recommendations.subCategory",
                         "recommendations.severityScore", "recommendations.publicExploit", "recommendations.activeAlert",
                         "recommendations.associatedThreats", "recommendations.remediationType", "recommendations.status",
                         "recommendations.configScoreImpact", "recommendations.exposureImpact", "recommendations.totalMachineCount",
                         "recommendations.exposedMachinesCount", "recommendations.nonProductivityImpactedAssets",
                         "recommendations.relatedComponent", "recommendations.hasUnpatchableCve", "recommendations.tags",
                         "recommendations.exposedCriticalDevices", "recommendations.software.1", "recommendations.vulnerabilities.1",
                         "recommendations.Vulnerabilities", "recommendations.Software", "recommendations.MachineReferences"}
                   )
                   else ExtractedText,

    // Select only columns that exist
    SafeSelect = Table.SelectColumns(
        ExpandedRecs,
        List.Intersect({Table.ColumnNames(ExpandedRecs), {"computerDnsName", "recommendations.recommendationName", "recommendations.id", "exposureLevel"}})
    ),

    // Rename safely
    RenameID = Table.RenameColumns(SafeSelect, {{"recommendations.id", "Recommendation ID"}}, MissingField.Ignore),
    RenameCols = Table.RenameColumns(RenameID, {
        {"computerDnsName", "Asset Name"},
        {"recommendations.recommendationName", "Asset Recommendations"},
        {"exposureLevel", "Exposure Level"}
    }, MissingField.Ignore)
in
    RenameCols



    let
    PageSize = 800,

    // Recursive function to fetch JSON and follow @odata.nextLink
    GetAllPages = (url as text) as table =>
        let
            // Fetch raw JSON
            response = Json.Document(Web.Contents(url)),

            // Extract "value" (the list of rows)
            rows = try response[value] otherwise {},

            // Convert list of records into a table
            tableRows =
                if List.Count(rows) > 0 then
                    Table.FromList(rows, Splitter.SplitByNothing(), {"Column1"})
                else
                    #table({}, {}),

            // Expand record fields into columns
            expanded =
                if Table.RowCount(tableRows) > 0 then
                    Table.ExpandRecordColumn(tableRows, "Column1", Record.FieldNames(rows{0}))
                else
                    tableRows,

            // Look for @odata.nextLink
            next = try Record.Field(response, "@odata.nextLink") otherwise null,

            // Recurse if more pages exist
            more =
                if next <> null then
                    @GetAllPages(next)
                else
                    #table({}, {}),

            // Combine current + later pages
            result = Table.Combine({expanded, more})
        in
            result,

    // First request (kick off paging loop)
    Source = GetAllPages(
        "https://api.security.microsoft.com/api/machines?$top=" & Text.From(PageSize) & "&$expand=recommendations"
    ),

    // Add OnboardedDate safely
    AddOnboardedDate = Table.AddColumn(Source, "OnboardedDate", each try Date.From([firstSeen]) otherwise null),

    // Shorten computerDnsName if present
    ShortName =
        if Table.HasColumns(AddOnboardedDate, "computerDnsName") then
            Table.TransformColumns(AddOnboardedDate, {{"computerDnsName", each Text.BeforeDelimiter(_, "."), type text}})
        else
            AddOnboardedDate,

    // Expand recommendations
    ExpandedRecs =
        if Table.HasColumns(ShortName, "recommendations") then
            Table.ExpandTableColumn(
                ShortName,
                "recommendations",
                {"id", "recommendationName"},
                {"Recommendation ID", "Asset Recommendations"}
            )
        else
            ShortName,

    // Select only required columns
    SafeSelect = Table.SelectColumns(
        ExpandedRecs,
        List.Intersect({
            Table.ColumnNames(ExpandedRecs),
            {"computerDnsName", "ExposureLevel", "OnboardedDate", "Recommendation ID", "Asset Recommendations"}
        })
    ),

    // Rename columns cleanly
    RenameCols = Table.RenameColumns(
        SafeSelect,
        {
            {"computerDnsName", "Asset Name"},
            {"ExposureLevel", "Exposure Level"}
        },
        MissingField.Ignore
    )
in
    RenameCols



let
    ODataSource = OData.Feed("https://api.security.microsoft.com/api/machines", null, [Implementation="2.0", MoreColumns=true]),
    AddOnboardedDate = Table.AddColumn(ODataSource, "OnboardedDate", each try [firstSeen] otherwise null),
    ChangeType = Table.TransformColumnTypes(AddOnboardedDate, {{"OnboardedDate", type date}}),
    ExtractedText = if Table.HasColumns(ChangeType, "computerDnsName") 
                    then Table.TransformColumns(ChangeType, {{"computerDnsName", each Text.BeforeDelimiter(_, "."), type text}})
                    else ChangeType
in
    ExtractedText