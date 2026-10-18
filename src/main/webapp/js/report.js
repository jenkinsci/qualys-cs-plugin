
function showReportsPage(reportObject){
	jQuery(document).ready(function() {
		drawSummaryTable(reportObject);
		drawBuildSummary(reportObject);
		drawTrendingChart(reportObject);
		drawVulnsCharts(reportObject);
		drawTables(reportObject);
	});
}

function setLabeledValues(selector, values) {
	var target = jQuery(selector).empty();
	values.forEach(function(value, index) {
		if(index > 0) {
			target.append(document.createElement("br"));
		}
		target.append(jQuery("<b>").text(value.label));
		target.append(document.createTextNode(" " + String(value.value)));
	});
}

function escapeHtml(value) {
	return jQuery("<div>").text(value == null ? "" : String(value)).html();
}

function renderText(data, type) {
	return type === "display" ? escapeHtml(data) : data;
}

function drawSummaryTable(reportObject){
	if(reportObject.qids){
		if(reportObject.qids.configured){
			jQuery("#qid-found .image-scan-status").removeClass("not-configured").addClass(reportObject.qids.result ? "ok" : "fail");
			setLabeledValues("#qid-found .image-scan-status .tooltip-text", [
				{label: "Configured:", value: reportObject.qids.configured},
				{label: "Found:", value: reportObject.qids.found ? reportObject.qids.found : "None"}
			]);
		}
	}
	if(reportObject.cveIds){
		if(reportObject.cveIds.configured ){
			jQuery("#cve-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cveIds.result ? "ok" : "fail");
			setLabeledValues("#cve-found .image-scan-status .tooltip-text", [
				{label: "Configured:", value: reportObject.cveIds.configured},
				{label: "Found:", value: reportObject.cveIds.found ? reportObject.cveIds.found : "None"}
			]);
		}
	}
	if(reportObject.cvss){
		if(reportObject.cvss.configured != null && reportObject.cvss.configured >= 0){			
			var version = "";
			if (reportObject.cvss.version == "3"){
				version = "3";
			} else{
				version = "2";
			}
			jQuery("#cvss-found .image-scan-status").removeClass("not-configured").addClass(reportObject.cvss.result ? "ok" : "fail");
			if(reportObject.cvss.version == "maxOfv2andv3") {
				setLabeledValues("#cvss-found .image-scan-status .tooltip-text", [
					{label: "Configured:", value: "Max. of CVSS2 or CVSS3 is greater than or equal to " + reportObject.cvss.configured},
					{label: "Found:", value: reportObject.cvss.found ? reportObject.cvss.found : "None"}
				]);
			}
			else{
				setLabeledValues("#cvss-found .image-scan-status .tooltip-text", [
					{label: "Configured:", value: "CVSSv" + version + " more than or equal to " + reportObject.cvss.configured},
					{label: "Found:", value: reportObject.cvss.found ? reportObject.cvss.found : "None"}
				]);
			}
		}
	}
	if(reportObject.software){
		if(reportObject.software.configured ){
			jQuery("#software-found .image-scan-status").removeClass("not-configured").addClass(reportObject.software.result ? "ok" : "fail");
			setLabeledValues("#software-found .image-scan-status .tooltip-text", [
				{label: "Configured:", value: reportObject.software.configured},
				{label: "Found:", value: reportObject.software.found ? reportObject.software.found : "None"}
			]);
		}
	}
	var severityObj = reportObject["severities"];
	for(var i=1; i<=5; i++){
		if(severityObj[i])
			if(!(severityObj[i].configured === null || severityObj[i].configured === -1)){
				jQuery("#sev" + i + "-found .image-scan-status").removeClass("not-configured").addClass(severityObj[i].result ? "ok" : "fail");
				setLabeledValues("#sev" + i + "-found .image-scan-status .tooltip-text", [
					{label: "Configured:", value: "more than " + severityObj[i].configured},
					{label: "Found:", value: severityObj[i].found !== null ? severityObj[i].found : "0"}
				]);
			}
	}
	if(reportObject.qids.excluded || reportObject.cveIds.excluded) {
		setLabeledValues("#excluded-items", reportObject.qids.excluded
			? [{label: "*Excluded QIDs:", value: reportObject.qids.excluded}]
			: [{label: "*Excluded CVEs:", value: reportObject.cveIds.excluded}]);
	}
	if(reportObject.potentialVulnsChecked)
		jQuery("#potential-checked").text("*Criteria applied to potential vulnerabilities as well.");
}

function showTab(qid) {
    jQuery("#vulnerabilities").hide();
    jQuery(".left-pill-item.vulns").removeClass("selected");
    jQuery(".left-pill-item.softwares").addClass("selected");
    jQuery("#installed-softwares").show();
    jQuery("#softwareTable_filter input").val("QID="+qid);
    jQuery("#softwareTable_filter input").focus();
    jQuery("#softwareTable_filter input").keydown();
    jQuery("#softwareTable_filter input").keyup();
};

function bytesToSize(bytes) {
   var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
   if (bytes == 0) return '0 Byte';
   var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
   return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
};

//Trending Chart
function drawTrendingChart(reportObject){
	if(reportObject.totalVulnsTrend.prev == null || reportObject.totalVulnsTrend.prev == "null"){
		jQuery("#trending-prev-job").hide();
	}
	
	var currentVulns = reportObject.totalVulnsTrend.current ;
	var prevVulns = reportObject.totalVulnsTrend.prev ;
	var c = jQuery("#trendVulns").get(0);
	var ctx = c.getContext("2d");
	
	var data1 = { 
					"labels" : ["Sev 5","Sev 4","Sev 3","Sev 2","Sev 1"], 
					"datasets" : [
								{ label : "Current Build", 
									backgroundColor : "rgba(126, 183, 255, 1)", 
									data : currentVulns ? currentVulns.reverse() : []
								},
								{ label : "Previous Build", 
									backgroundColor : "rgba(192,192,192, 1)", 
									data : (prevVulns && prevVulns != "null") ? prevVulns.reverse() : []
								}
				]};
								
	var options = {
		plugins: {
            legend: {
                display: false
            }
        },
		scales: {
		  x: {
			grid: {
			  display: false
			}
		  },
		  y: {
			grid: {
			  display: false
			}
		  }
    	}
	}
	if(currentVulns && currentVulns.length > 0 ){
		var barChart = new Chart(ctx, {type: 'bar', data: data1, options: options});
	}else{
		jQuery(".trending-chart-legend li").hide();
		jQuery("div#trending div.report-chart-div").text("Unable to show Trending chart!");
		jQuery("div#trending div.report-chart-div").css({"margin-top":"95px", "margin-left":"50px"});
	}
}
//End Trending chart

function drawVulnsCharts(reportObject){
	// ------Confirmed Vulnerabilities Chart
	var d = reportObject.confirmedVulnsBySev;
	var count = Array();
	var severity = Array();
	var show_tooltip = true;
	
	var potentialVulnsObj = reportObject.potentialVulnsBySev;
	var c = jQuery("#sevVulns").get(0);
	var ctx = c.getContext("2d");
	
	
	var i = 0;
	var total = 0;
	for (var key in d) {
		count[i] = d[key];
	   severity[i] = key;
	   total += count[i]; 
	   i++;
	}
	
	var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
	var labels = count; 
	jQuery("#confTotCount").text(total);
	if(! count.some(el => el !== 0)){
		count = ["1", "1", "1", "1", "1"];
		severity = ["1", "2", "3", "4", "5"];
		labels = ["0", "0", "0", "0", "0"];	
		colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		show_tooltip = false;
	}
	
	var options = {
	    responsive: true,
        plugins: {
            legend: {
                display: true,
                position: 'right'
            },
            tooltip: 
            {
              enabled: show_tooltip,
              callbacks: 
              {
                label: function(context) 
                {
                    var label = context.label;
                    return label;
             	}     
              }
           }
        }
	};
		
	var confirmedVulnsData = {
		datasets : [
			{
			data : [count[4].toString(), count[3].toString(), count[2].toString(), count[1].toString(), count[0].toString()],
			backgroundColor : [
				colors[4],
				colors[3],
				colors[2],
				colors[1],
				colors[0]
				]
			}
		],
		labels: [
			"Sev " + severity[4].toString() + " (" + labels[4] + ")",
			"Sev " + severity[3].toString() + " (" + labels[3] + ")",
			"Sev " + severity[2].toString() + " (" + labels[2] + ")",
			"Sev " + severity[1].toString() + " (" + labels[1] + ")",
			"Sev " + severity[0].toString() + " (" + labels[0] + ")",
		]
	};
	var chart = new Chart(ctx, {type: 'doughnut', data: confirmedVulnsData, options: options});	

	// ------Potential Vulnerabilities Chart
	count = Array();
	severity = Array();
	var c = jQuery("#typeVulns").get(0);
	var ctx = c.getContext("2d");
	
	var i = 0;
	total = 0;
	for (var key in potentialVulnsObj) {
		count[i] = potentialVulnsObj[key];
	   severity[i] = key;  
	   total += count[i];
	   i++;
	}
	
	labels = count;	
	colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
	
	jQuery("#potTotCount").text(total);
	if(!(count.some(el => el !== 0))){
		count = ["1", "1", "1", "1", "1"];
		severity = ["1", "2", "3", "4", "5"];
		labels = ["0", "0", "0", "0", "0"];	
		colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		show_tooltip = false;
	}
	
	var potentialVulnsData = {
		datasets : [
			{
			data : [count[4].toString(), count[3].toString(), count[2].toString(), count[1].toString(), count[0].toString()],
			backgroundColor : [
				colors[4],
				colors[3],
				colors[2],
				colors[1],
				colors[0]
				]
			}
		],
		labels: [
			"Sev " + severity[4].toString() + " (" + labels[4] + ")",
			"Sev " + severity[3].toString() + " (" + labels[3] + ")",
			"Sev " + severity[2].toString() + " (" + labels[2] + ")",
			"Sev " + severity[1].toString() + " (" + labels[1] + ")",
			"Sev " + severity[0].toString() + " (" + labels[0] + ")",
		]
	}; 		
	var chart = new Chart(ctx, {type: 'doughnut', data: potentialVulnsData, options: options});	

	// ------Patchability Chart
	var patchableData = reportObject.patchability;
	c = jQuery("#patchVulns").get(0);
	ctx = c.getContext("2d");
	
	colors = ["#5D9933","#D61E1C" ];
	if(! (patchableData['yes'] == '0' && patchableData['no'] == '0')){
		count = [patchableData['yes'], patchableData['no']];
		labels = count;
		show_tooltip = false;
	}else{
		count = ["1", "1"];
		labels = ["0", "0"];
		colors = ["#B0BFC6", "#B0BFC6"];
	}
  	var patchVulnsdata = {
		datasets : [
			{
			data : [count[1].toString(), count[0].toString()],
			backgroundColor : [
				colors[1],
				colors[0]
				]
			}
		],
		labels: [
			"No " + "(" + labels[1] + ")" ,
			"Yes " + "(" + labels[0] + ")",
		]
	};
	var patchVulnsChart = new Chart(ctx, {type: 'doughnut', data: patchVulnsdata, options: options});
}

function drawBuildSummary(reportObject){
	jQuery('#build-status').text( (reportObject.imageSummary.pass == "true" || reportObject.imageSummary.pass == true)? "Success" : "Failed");
	
	if(reportObject.imageSummary.pass === false || reportObject.imageSummary.pass == "false"){
		jQuery('#build-status').css('color', 'red');
		jQuery('.status-image').addClass('failed');
		jQuery('.status-image').removeClass('success');
	}else{
		jQuery('#build-status').css('color', 'green');
		jQuery('.status-image').removeClass('failed');
		jQuery('.status-image').addClass('success');
	}
	
	jQuery("#image-tags").text("-");
	if(reportObject.imageSummary.hasOwnProperty("Tags") && reportObject.imageSummary.Tags){
		var tags = reportObject.imageSummary.Tags.filter(function (el) { return el != null;	});
		var tagsStr = tags.join(', ');
		jQuery("#image-tags").text(tagsStr);
	}
	
	var size = reportObject.imageSummary.size;
	var sizeStr = bytesToSize(parseInt(size));
	jQuery("#image-size").text(sizeStr);
}
	
function format ( d ) {
	return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
		    '<tr>'+
			'<td>CVSS Base Score: ' + escapeHtml(d.cvssInfo.baseScore) + '</td>'+
			'<td>CVSS Temporal Score: '+ escapeHtml(d.cvssInfo.temporalScore) +'</td>'+
		    '</tr>'+
		    '<tr>'+
			'<td>CVSS3 Base Score: ' + escapeHtml(d.cvss3Info.baseScore) + '</td>'+
			'<td>CVSS3 Temporal Score: '+ escapeHtml(d.cvss3Info.temporalScore) +'</td>'+
		    '</tr>'+
		    '<tr>'+
		        '<td>CVSS Access Vector: </td>'+
		        '<td>'+escapeHtml(d.cvssInfo.accessVector)+'</td>'+
		    '</tr>'+
		    '<tr>'+
	            '<td>CVE Ids</td>'+
	            '<td>'+escapeHtml(d.cveids)+'</td>'+
	        '</tr>'+
	        '<tr>'+
	            '<td>Result</td>'+
	            '<td>'+escapeHtml(d.result)+'</td>'+
	        '</tr>'+
    '</table>';
}

function drawTables(reportObject){
	var vulns = reportObject.vulnsTable;
	var layers = reportObject.layersTable;
	var installedSoftwares = reportObject.softwaresTable;
	
	if(layers && layers.length == 0){
		jQuery("#layers").hide();
		jQuery(".left-pill-item.layers").hide();
	}
	
	var softwareTable = jQuery('#softwareTable').DataTable({
		 "language": {
    		"emptyTable": "No Softwares installed"
		 },
		 
		"dom": '<"soft-table-top"l<"softwares-custom-filters"><"#search" "search-box">>frt<"vulns-table-bottom"ip><"clear">',
        "aaData": installedSoftwares,
        "aoColumns":[
            { "mData": "name", "render": renderText },
            { "mData": "version" },
            { "mData": "fixVersion", "render": renderText, sDefaultContent :  '' },
            { "mData": "vulnerabilities", sDefaultContent :  ''  },
            { "mData": "vulnerabilities", sDefaultContent :  ''  },
            { "mData": "fixVersion", sDefaultContent :  ''  }
        ],
        'aoColumnDefs': [
        	{ "sTitle": "Name", "aTargets": [0] },
            { "sTitle": "Installed Version", "aTargets": [1],
            "render":  function ( data, type, row ) {
							if(type !== "display") {
								return data;
							}
                            var fixedVersion = row["fixVersion"];
                            if (fixedVersion!= null && fixedVersion!= '') {
                                return '<div class="status-image vuln"></div>'+escapeHtml(data);
                            }
                            else {
                                return escapeHtml(data);
                            }
                       }
            },
            { "sTitle": "Fixed In Version", "aTargets": [2]},
            { "sTitle": "Total QID", "aTargets": [3] , visible:false,
            "render":  function ( data, type, row ) {
                            var vulnerabilities = row["vulnerabilities"];       
                            return renderText(JSON.stringify(vulnerabilities), type);
                       }
            },
            { "sTitle": "QID", "aTargets": [4] , visible:false,
            "render":  function ( data, type, row ) {
                                var QIDString = "";
                                var vulnerabilities = row["vulnerabilities"]; 
                                if (vulnerabilities!= null && vulnerabilities.length > 0) {        
                                    vulnerabilities.forEach(function(key) {
                                        QIDString +="QID="+key.qid+",";
                                    });        
                                }                                    
                            return renderText(QIDString, type);
                       }
            },
            { "sTitle": "Patchable", "aTargets": [5] , visible:false,
            	"render":  function ( data, type, row ) {
                            var fixedVersion = row["fixVersion"];
                            if (fixedVersion!= null && fixedVersion!= '') {
                                return true;
                            }
                            else {
                                return false;
                            }
                       }
            }
        ],
        "order": [[ 0, "desc" ]]
    });

	//Layers Table
    var layersTable = jQuery('#layersTable').DataTable({            
		 "language": {
    		"emptyTable": "No layers found"
		 },   			 
		"dom": '<"layers-table-top"l<"#search" "search-box">>frt<"layers-table-bottom"ip><"clear">',
        "aaData": layers,
        "aoColumns":[
        	{ "mData": "",
              "mData": "createdBy"
            }                
        ],
        'aoColumnDefs': [
        	{ "sTitle": "#", "aTargets": [0], visible: true,
                render : function ( data, type, row, meta ) {
                    return meta.row + meta.settings._iDisplayStart + 1;      
                }
            },
            { "sTitle": "Command", "aTargets": [1],
                render : function ( data, type, row ) { 
                     return renderText(row["createdBy"], type);
                }
            }
        ]
    });   
           
     jQuery('#softwareTable_filter input').keyup(function(){
        var searchInput = jQuery("#softwareTable_filter input").val(); 
        softwareTable.columns().search('').draw(); 
    });


    //Vulns Table
	var table = jQuery('#vulnsTable').DataTable({             
		 "language": {
    		"emptyTable": "No vulnerabilities found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[
        	 {
	            "className": 'details-control',
	            "orderable": false,
	            "data":      null,
	            "defaultContent": ''
	        },
            { "mData": "qid", "render": renderText },
            {
                "className": 'fail',
                "orderable": false,
                "data":      null,
                "defaultContent": ''
            },
            { "mData": "title", "render": renderText },
            { "mData": "severity", "render": renderText },
            { "mData": "cveids" },
            { "mData": "category", "render": renderText },
            { "mData": "firstFound" },
            { "mData": "software"},
            { "mData": "patchAvailable", "render": renderText},
            { "mData": "threatIntel"},
            { "mData": "threatIntel"},
            { "mData": "typeDetected", "render": renderText }
            
        ],
        'aoColumnDefs': [
        	{ "sTitle": "", "aTargets": [0] },                              
            { "sTitle": "QID", "aTargets": [1] },
            { "sTitle": "", "aTargets": [2],
                "render":  function ( data, type, row ) {
                var sev = parseInt(data.severity);
                if(reportObject && reportObject.severities){
                    var severityObj = reportObject["severities"];
                	for(var i=1; i<6; i++)
                	{
                	    if(severityObj && severityObj[i])
                		{
                		    if(severityObj[i].configured != null && severityObj[i].configured > -1 && severityObj[i].result != undefined && severityObj[i].result!= null)
                            {
                			    if(sev==i && severityObj[i].result == false )
                				{
                				    return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

                				}

                			}
                		}
                	}
                }
                if(reportObject && reportObject.qids)
                {
                    var configuredQids = reportObject["qids"].configured;
                    if(configuredQids && configuredQids.length > 0)
                    {
                        if(configuredQids.indexOf(row.qid) != -1)
                    	{
                    	    return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

                    	}
                    }
                }
                if(reportObject && reportObject.cveIds)
                {
                    var configuredcveids = reportObject["cveIds"].configured;
                    if(configuredcveids != null && configuredcveids.length > 0)
                    {
                        cveids = row.cveids
                        for (let i = 0; i < cveids.length; i++) {
                            if (configuredcveids.indexOf(cveids[i]) != -1)
                            {
                                return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

                            }
                        }
                    }
                }
                if(reportObject && reportObject.software)
                {
                    var configuredsoftware = reportObject["software"].configured;
                    if(configuredsoftware != null && configuredsoftware.length > 0)
                    {
                        if (row["software"] != null){
                            for (let i = 0; i < row["software"].length; i++) {
                                if (configuredsoftware.indexOf(row["software"][i].name) != -1){
                                    return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

                               }
                            }
                        }
                    }
                }

                if(reportObject && reportObject.cvss){
                    var configuredcvss = reportObject.cvss.configured;
                    var configuredversion = reportObject.cvss.version;
                    if (configuredcvss != null) {
                       if (configuredversion == ""){
                            configuredversion = "2"
                       }
                       if(configuredversion == "2"){
                            if (row["cvssInfo"].baseScore >= configuredcvss){
                         	    return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';
                         	}
                       }
                       else if(configuredversion == "3"){
                            if (row["cvss3Info"].baseScore >= configuredcvss){
                                return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';
                            }
                       }
                       else{
                            if (Math.max(row["cvss3Info"].baseScore ,row["cvssInfo"].baseScore) >= configuredcvss){
                                return '<img src="/plugin/qualys-cs/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';
                            }
                       }
                    }
                }
                }
            },
            { "sTitle": "Title", "aTargets": [3] },
            { "sTitle": "Severity", "aTargets": [4] },
            { "sTitle": "CVEs", "aTargets": [5] ,
            	"render":  function ( data, type, row ) {
                if(type !== "display") {
                    return data;
                }
                if(data.length > 1){
                    return escapeHtml(data[0]) +' + <a href="#" class="more-cve-records">' + (data.length - 1) +' more</a>';
                }else{
                    return escapeHtml(data);
                }
            }
            },
            { "sTitle": "Category", "aTargets": [6] },
            { "sTitle": "Age", "aTargets": [7] ,
            	"render":  function ( data, type, row ) {
                				var today= new Date();
                				var pubDate = new Date(Number(data));
                				var diff = Math.abs(today - pubDate)/1000;
                				var days = Math.floor(diff / 86400);
                				return days + ' Day' + ((days > 1) ? 's' : '');
            			}
            },
            { "sTitle": "Installed Software", "aTargets": [8],
            	"render":  function ( data, type, row ) {
                            var numInstalledSoftwares = row["software"];
                            var count = 0;
                            for(var key in numInstalledSoftwares) {
                               if (numInstalledSoftwares.hasOwnProperty(key)) {
                                count++;
                               }
                            }
                            if (count == 0) {
                                return '<div style="text-align:center;">-</div>';
                            }
                            else {
                                return '<div style="text-align:center;"><a href="#" class="show-software-tab">'+count+'</a></div>';
                            }                    			
            			} },
            { "sTitle": "Patchable", "aTargets": [9], visible:false},
            { "sTitle": "Exploitable", "aTargets": [10], visible:false,
            	"render":  function ( data, type, row ) {
                				return (data.easyExploit && data.easyExploit != null) ? 'true' : 'false';
            			}
            },
            { "sTitle": "Associated Malware", "aTargets": [11], visible:false,
            	"render":  function ( data, type, row ) {
                				return (data.malware && data.malware != null) ? 'true' : 'false';
            			}
            },
            { "sTitle": "Confirmed", "aTargets": [12], visible:false}
        ],
        "order": [[ 3, "desc" ]]
    });
    
    jQuery('#vulnsTable tbody').on('click', 'td.details-control', function () {
        var tr = jQuery(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format(row.data()) ).show();
            tr.addClass('shown');
        }
    });
    
    jQuery("#vulnsTable tbody").on("click", ".more-cve-records", function(e){
    	var tr = jQuery(this).closest('tr');
    	var row = table.row( tr );
    	row.child( format(row.data()) ).show();
        tr.addClass('shown');
        return false;
    });

    jQuery("#vulnsTable tbody").on("click", ".show-software-tab", function(e){
        e.preventDefault();
        var row = table.row(jQuery(this).closest('tr')).data();
        showTab(row.qid);
    });
    
    
    jQuery(".softwares-custom-filters").html(
    	'<div class="sev-filter-div">' + 
    	'<span class="filters-label">Show Only: </span>' + '</div>'+ 
    	'<ul class="filters-list">' +
    	'<li><input class="custom-filter-checkbox" type="checkbox" id="sw-patchable" value="sw-patchable">  <label for="sw-patchable" class="checkbox-title"> Patchable  </li>' +
    	'</ul>' 
    );
    jQuery(".custom-filters").html(
    	'<div class="sev-filter-div">' + 
    	'<span class="filters-label">Show Only: </span>' + 
    	'<span class="sev-filter-label" >Severity </span>' + 
    	'<select class="severity-dropdown">' + 
    	'<option value="">All</option>' +
    	'<option value="5"> 5 </option>' +
    	'<option value="4"> 4 </option>' +
    	'<option value="3"> 3 </option>' +
    	'<option value="2"> 2 </option>' +
    	'<option value="1"> 1 </option>' +
    	'</select>' +
    	'</div>'+
    	'<ul class="filters-list">' +
    	'<li><input class="custom-filter-checkbox" type="checkbox" id="confirmed" value="confirmed">  <label for="confirmed" class="checkbox-title"> Confirmed  </li>' +
    	'<li><input class="custom-filter-checkbox" type="checkbox" id="patchable" value="patchable">  <label for="patchable" class="checkbox-title"> Patchable  </li>' +
    	'<li><input class="custom-filter-checkbox" type="checkbox" id="exploitable" value="exploitable"><label for="exploitable" class="checkbox-title" > Exploitable </li>' +
    	'<li><input class="custom-filter-checkbox" type="checkbox" id="malware" value="malware"> <label for="malware" class="checkbox-title" > Associated Malware </li>' +
    	'</ul>' 
    );
    
    jQuery(".custom-filters-left").html(
    	
    );
    
    jQuery('.severity-dropdown').on('change', function(e){
    	 var optionSelected = jQuery("option:selected", this);
		 var valueSelected = this.value;
		 table.columns(4).search( valueSelected ).draw();
    });
    
    jQuery(".custom-filter-checkbox").on("change", function(e){
    	switch(this.value){
    		case 'sw-patchable':
						var value = (this.checked)? 'true' : '';
						softwareTable.columns(5).search( value ).draw();
						break;
		}
    });
    
    jQuery(".custom-filter-checkbox").on("change", function(e){
		switch(this.value){
			case 'confirmed':
						var value = (this.checked)? 'confirmed' : '';
						table.columns(12).search( value ).draw();
						break;
			case 'patchable':
						var value = (this.checked)? 'true' : '';
						table.columns(9).search( value ).draw();
						break;
						
			case 'exploitable': 
						var value = (this.checked)? 'true' : '';
						table.columns(10).search( value ).draw();
						break;
			case 'malware': 
						var value = (this.checked)? 'true' : '';
						table.columns(11).search( value ).draw();
						break;
		}
	});
}	
	
	
