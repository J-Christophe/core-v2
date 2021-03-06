{
	/* 
	 * Comment block
	 */
	// Comment on one line

    "debug": false,
    "coordSystem": "EQ", // Default coordinate system
    "navigation": {
		// "initTarget": [14.06,-1.252403], // HST
		// "initTarget": [4.3500, 3.0794], //Asteroides
		// "initTarget": [84.7625, -69.1689], //Doradus
		// "initTarget": [258.5167, -12.9106], // OS/Samp bug
		//"initTarget": [199.87550000000002, -12.743169444444444], // Footprint
		//"initTarget": [1.0, 89.0], // Polaris
                "initTarget": [85.2500, -2.4608],
		"initFov": 20,
		"inertia": true,
		"minFov": 0.001,
		"zoomFactor": 0
	},
    // SiTools2 services configuration
	"nameResolver": {
		"baseUrl": "/sitools/mizar/plugin/nameResolver",
		"zoomFov": 2
	},
	"reverseNameResolver": {
		"baseUrl": "/sitools/mizar/plugin/reverseNameResolver/"
	},
	"coverageService": {
		"baseUrl": "/sitools/mizar/plugin/coverage?moc="
	},
        "solarObjects": {
                "baseUrl": "/sitools/mizar/plugin/solarObjects/"
        },
	"votable2geojson": {
		"baseUrl": "/sitools/mizar/plugin/votable2geojson"
	},
	"cutOut": {
		"baseUrl": "/sitools/cutout"
	},
	"zScale": {
		"baseUrl": "/sitools/zscale"
	},
	"healpixcut": {
       "baseUrl": "/sitools/healpixcut"
	},
	"shortener": {
		"baseUrl": "/sitools/shortener"
	},
	"stats": {
		"verbose": false,
		"visible": false
	},
	"layers":
	[
		/**
		 *	Built-in star/constellation catalogs
		 */
		{
			"category": "Other",
			"type": "GeoJSON",
			"name": "Constellations",
			"icon": "css/images/constellation_icon.png",
			"attribution": "Constellation coming from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><object width='24' height='16' data=\"css/images/cds.svg\" type=\"image/svg+xml\"></object></a>",
			"description": "Constellation shapes from VizieR Catalogue",
			"data": {
				"type": "constellation",
				"nameUrl": "data/ConstellationNames.tsv",
				"catalogueUrl": "data/bound_20.dat"
			},
			"visible": false,
			"pickable" : false,
			"color": "rgb(8, 59, 167)"
		},
		{
			"category": "Other",
			"type": "GeoJSON",
			"name": "Brighten stars",
			"icon": "css/images/star_icon.png",
			"attribution": "The most brighten stars coming from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><object width='24' height='16' data=\"css/images/cds.svg\" type=\"image/svg+xml\"></object></a>",
			"description": "The most brighten stars from VizieR Catalogue",
			"data": {
				"type": "star",
				"nameUrl": "data/Names.tsv",
				"catalogueUrl": "data/Catalogue.tsv"
			},
			"visible": true,
			"opacity": 100,
			"pickable" : false,
			"color": "white"
		},
		/**
         * Coordinate grids
		 */
		{
			"category": "Coordinate systems",
			"type": "coordinateGrid",
			"name": "Equatorial grid",
			"visible": false,
			"coordSystem": "EQ",
			"color": "white",
			"latFormat": "DMS",
			"longFormat": "HMS"
		},
		{
			"category": "Coordinate systems",
			"type": "coordinateGrid",
			"name": "Galactic grid",
			"visible": false,
			"coordSystem": "GAL",
			"color": "red",
			"latFormat": "Deg",
			"longFormat": "Deg"
		},
		/**
		 *	Alasky healpix sources
		 *
		 *	Plugin: Proxy Healpix Image cache
		 *	urlClient: http://alasky.u-strasbg.fr or http://healpix.ias.u-psud.fr/
		 */
		{
			"type": "healpix",
			"name": "WISE RGB",
			"baseUrl": "/sitools/Alasky/WISE/RGB/",
			"description": "WISE color",			
			"visible": false,
			"background": true,	
                        "coordSystem": "GAL",
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/Missions/wise.html\" target=\"_blank\"><img src=\"/sitools/upload/wise.svg\" width='24' height='16'/></a> color background provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><object width='24' height='16' data=\"css/images/cds.svg\" type=\"image/svg+xml\"></object></a>",
			"numberOfLevels": 5
		},
		{
			"type": "healpix",
			"name": "SpitzerI1I2I4color",
			"baseUrl": "/sitools/Alasky/SpitzerI1I2I4color",
			"description": "Spitzer color",			
			"visible": false,
			"background": true,	
                        "coordSystem": "GAL",
                        "attribution":"<object width='24' height='16' data=\"/sitools/upload/spitzer.svg\" type=\"image/svg+xml\"></object> color background provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><object width='24' height='16' data=\"css/images/cds.svg\" type=\"image/svg+xml\"></object></a>",
			"numberOfLevels": 9
		},
		{
			"type": "healpix",
			"name": "IRIS",
			"baseUrl": "/sitools/Alasky/IRISColor",
			"description": "IRIS color",
			"icon": "css/images/star_icon.png",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
                        "attribution": "IRIS background from <img width='24' height='16' src=\"css/images/cds.svg\" />",
			"numberOfLevels": 2
		},
		{ 
			"type": "healpix",
			"name": "Deep CFHTLS",
			"baseUrl": "/sitools/Alasky/CFHTLS-T0007b/Deep/RGB-UGIm",
			"description": "Deep CFHTLS from CDS",
			"attribution": "Deep CFHTLS background from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"visible": false,
			"background": true,
			"numberOfLevels": 11
		},
		{ 
			"type": "healpix",
			"name": "CFHTLS Wide",
			"baseUrl": "/sitools/Alasky/CFHTLS-T0007b/Wide/RGB-UGIm",
			"description": "CFHTLS-W-Colored (UGI)",
            "attribution": "TERAPIX - Healpixed by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"visible": false,
			"background": true,
			"numberOfLevels": 10
		},
		{ 
			"type": "healpix",
			"name": "2MASS",
			"baseUrl": "/sitools/Alasky/2MASS/Color",
			"description": "Infrared 2MASS colored survey from NASA, healpixed by CDS",
			"attribution": "2MASS background from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"visible": false,
			"background": true,
			"numberOfLevels": 8
		},
		{ 
			"type": "healpix",
			"name": "RASS",
			"baseUrl": "/sitools/Alasky/RASS",
			"description": "RASS-ROSAT X-Ray All-Sky Survey",
			"attribution": "Distributed by MPE - Healpixed by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"visible": false,
			"background": true,
			"numberOfLevels": 3
		},
		{ 
			"type": "healpix",
			"name": "NVSS",
			"baseUrl": "/sitools/Alasky/NVSS/intensity",
			"description": "NVSS intensity maps (1.4GHz)",
			"visible": false,
			"background": true,
			"numberOfLevels": 4
		},
		{ 
			"type": "healpix",
			"name": "DSS",
			"baseUrl": "/sitools/Alasky/DssColor",
			"description": "Digital Sky Survey from CDS",
			"attribution": "DSS background from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"visible": true,
			"background": true,
			"numberOfLevels": 8
		},
		{			
			"type": "healpix",
			"name": "SDSS",
			"baseUrl": "/sitools/Alasky/SDSS/Color",
			"description": "Sloan Digital Sky Survey from CDS",
			"attribution": "SDSS background from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"icon": "css/images/star_icon.png",
			"visible": false,
			"background": true
		},
		/**
		 *	Plack FITS supported surveys
		 */
		// Background
		{
			"type": "healpix",
			"name": "PlanckCMB",
			"baseUrl" : "/sitools/Alasky/PLANCK/CMB",
			"description": "Planck survey from CDS",
			"visible": false,
			"background": true,
			"dataType": "jpg",
			"fitsSupported": true,
			"coordSystem": "GAL",
			//"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_857_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
		},
        {
			"type": "healpix",
			"name": "Planck-HFI-857",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI857",
			"description": "PLANCK HFI 857 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_857_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },
        {
			"type": "healpix",
			"name": "Planck-HFI-545",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI545",
			"description": "PLANCK HFI 545 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_545_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },
        {
			"type": "healpix",
			"name": "Planck-HFI-353",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI353",
			"description": "PLANCK HFI 353 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_353_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },
        {
			"type": "healpix",
			"name": "Planck-HFI-217",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI217",
			"description": "PLANCK HFI 217 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_217_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },
        {
			"type": "healpix",
			"name": "Planck-HFI-143",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI143",
			"description": "PLANCK HFI 143 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_143_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },
        {
			"type": "healpix",
			"name": "Planck-HFI-100",
			"baseUrl": "/sitools/Alasky/PLANCK/HFI100",
			"description": "PLANCK HFI 100 from CDS",
			"visible": false,
			"background": true,
			"coordSystem": "GAL",
			"fitsSupported": true,
			"dataType": "jpg",
			"availableServices": [ { "name": "HEALPixCut", "fileName": "HFI_SkyMap_100_2048_R1.10_nominal.fits"	} ],
			"numberOfLevels": 2,
                         "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
        },

		// Overlay
		{
			"category": "Image",
			"type": "healpix",
			"name": "PlanckCMB",
			"baseUrl" : "/sitools/Alasky/PLANCK/CMB",
			"description": "Planck survey from CDS",
			"visible": false,
			"background": false,
			"dataType": "jpg",
			"fitsSupported": true,
			"coordSystem": "GAL",
                        "attribution":"<a href=\"http://irsa.ipac.caltech.edu/data/Planck/release_1/all-sky-maps/\" target=\"_blank\"><img src=\"/sitools/upload/planck.svg\" width='20' height='20'/></a> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
		},
		/**
		 *	Healpix grid
		 */
		{
			"category": "Other",
			"type": "healpixGrid",
			"name": "Healpix grid",
			"outline": true
		},
		/**
		 *	IAS PLWSAG Healpix imagery
		 *
		 *	Plugin: Proxy Healpix Image cache
		 *	urlClient: http://healpix.ias.u-psud.fr/PLWSAG-4ALLSKY
		 */
		{
			"category": "Herschel-SAG4",
			"type": "healpix",
			"name": "PLWSAG-4ALL",
			"baseUrl": "/sitools/proxytest/PLWSAG-4ALLSKY/",
			"description": "PLWSAG-4ALL",
			"attribution": "PLWSAG-4ALLSKY provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"visible": false,
			"background": false,
			"dataType": "jpg",
            	        "numberOfLevels": 5,
            	        "fitsSupported": true
		},
		/**
		 *	IAS PMWSAG Healpix imagery
		 *
		 *	Plugin: Proxy Healpix Image cache
		 *	urlClient: http://healpix.ias.u-psud.fr/PMWSAG-4ALLSKY/
		 */
		{
			"category": "Herschel-SAG4",
			"type": "healpix",
			"name": "PMWSAG-4ALLSKY",
			"baseUrl": "/sitools/proxytest/PMWSAG-4ALLSKY/",
			"description": "PLWSAG-4ALL",
			"attribution": "PLWSAG-4ALL provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"visible": false,
			"background": false,
			"dataType": "jpg",
            	        "numberOfLevels": 5,
            	        "fitsSupported": true
		},
		/**
		 *	IAS PSWSAG Healpix imagery
		 *
		 *	Plugin: Proxy Healpix Image cache
		 *	urlClient: http://healpix.ias.u-psud.fr/PSWSAG-4ALLSKY/
		 */
		{
			"category": "Herschel-SAG4",
			"type": "healpix",
			"name": "PSWSAG-4ALLSKY",
			"baseUrl": "/sitools/proxytest/PSWSAG-4ALLSKY/",
			"description": "PSWSAG-4ALLSKY",
			"attribution": "PSWSAG-4ALLSKY provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"visible": false,
			"background": false,
			"dataType": "jpg",
            	        "numberOfLevels": 5,
            	        "fitsSupported": true
		},
		/**
		 *	IAS RGBSAG-4ALLSKYfromPNG Healpix imagery
		 *
		 *	Plugin: Proxy Healpix Image cache
		 *	urlClient: http://healpix.ias.u-psud.fr/SAG-4_RGB/
		 */
		{
			"category": "Herschel-SAG4",
			"type": "healpix",
			"name": "SAG4-Herschel-RGB",
			"baseUrl": "/sitools/proxytest/SAG-4_RGB",
			"description": "combined bands (PSW, PMW, PLW)",
			"attribution": "SAG4-Herschel-RGB provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"visible": false,
			"background": false,
			"dataType": "png",
            	        "numberOfLevels": 5,
            	        "fitsSupported": true
		},
		/**
		 *	Layer initialized from GeoJSON file
		 */
		{
			"category": "Image",
			"type": "GeoJSON",
			"data": {
				"type": "JSON",
				"url": "data/serviceHealpix.json"
			},
			"name": "Doradus",
			"attribution": "Doradus data from ESO",
			"visible": true
		},
		/**
		 *	Doradus Healpix raster layer
		 */
/**
*		{
*			"category": "Image",
*			"type": "healpix",
*			"name": "DoradusPNG",
*			"baseUrl": "http://demonstrator.telespazio.com/doradus",
*			"description": "Doradus",
*			"attribution": "CDS",
*			"visible": false,
*			"background": false,
*			"dataType": "png",
*			"fitsSupported": true,
*			"numberOfLevels": 9
*		},
*/
		/**
		 *	OpenSearch SOLR Herschel layer
		 *
		 *	Plugin: OpenSearch Application
		 *	queryShape: healpix
		 *	healpixScheme: NESTED
		 *	solrCore: herschel
		 */
		{
                        "category": "Herschel-SAG4",
			"type": "DynamicOpenSearch",
			"dataType": "line",
			"name": "Pacs-SAG4-Herschel",
			"serviceUrl": "/sitools/oherschel",
			"visible": false,
                        "description": "SAG-4 : Evolution of interstellar dust (Herschel Guaranteed Time Key Project prepared by the ISM Specialist Astronomy Group of the SPIRE consortium) ",
			"attribution": "SAG4 provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"minOrder": 4,
			"availableServices": [ "OpenSearch", "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch SOLR Herschel layer
		 *
		 *	Plugin: OpenSearch Application
		 *	queryShape: healpix
		 *	healpixScheme: NESTED
		 *	solrCore: spire-herschel
		 */
		{
                        "category": "Herschel-SAG4",
			"type": "DynamicOpenSearch",
			"dataType": "line",
			"name": "Spire-SAG4-Herschel",
			"serviceUrl": "/sitools/spireherschel",
			"visible": false,
			"minOrder": 4,
                        "description": "SAG-4 : Evolution of interstellar dust (Herschel Guaranteed Time Key Project prepared by the ISM Specialist Astronomy Group of the SPIRE consortium) ",
			"attribution": "SAG4 provided by <a href=\"http://idoc-herschel.ias.u-psud.fr/\" target=\"_blank\"><img width='28' height='16' src=\"/sitools/upload/idoc.svg\" /></a>",
			"availableServices": [ "OpenSearch", "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch SOLR Fuse layer
		 *
		 *	Plugin: OpenSearch Application
		 *	queryShape: healpix
		 *	healpixScheme: NESTED
		 *	solrCore: fuse
		 */
/**		{
*			"type": "DynamicOpenSearch",
*			"dataType": "point",
*			"name": "Fuse (OpenSearch)",
*			"serviceUrl": "/sitools/ofuse",
*			"visible": false,
*			"minOrder": 4,
*			"accuracyOrder" : 10,
*			"color": "#FFCC11",
*			"displayProperties": [ "ra", "dec", "src_type", "dateobs", "imageSize" ],
*			"useCluster": true,
*			"availableServices": [ "OpenSearch", "Moc", "XMatch" ]
*		},
*/
		/**
		 *	OpenSearch SIA ESO layer
		 *
		 *	Plugin: VO OpenSearchApplication for Sia
		 *	siaSearchUrl: http://archive.eso.org/apps/siaserver/EsoProxySiap?
		 */
		{
			"category": "Image",
			"type": "DynamicOpenSearch",
			"dataType": "line",
			"name": "ESO",
			"serviceUrl": "/sitools/eso/siap",
                        "displayProperties": [ "identifier","Instrument","Telescope name","quicklook"],
			"visible": false,
                        "attribution":"<a href=\"http://archive.eso.org/cms.html\" target=\"_blank\"><img width='28' height='28' src=\"/sitools/upload/eso.svg\"></a>Science Archive Facility",
			"minOrder": 4,
			"invertY": true
		},
		/**
		 *	OpenSearch Sia HST layer
		 *
		 *	Plugin: VO OpenSearch Application for Sia
		 *	siaSearchUrl: http://archives.esac.esa.int/hst/hst-vo/hla_sia?REQUEST=queryData&
		 */
		{
			"category": "Image",
			"type": "DynamicOpenSearch",
			"dataType": "line",
			"name": "HST",
			"serviceUrl": "/sitools/sia",
                        "description":"Hubble Space Telescope (HST) is an orbiting astronomical observatory operating from the near-infrared into the ultraviolet. Launched in 1990 and scheduled to operate through 2010, HST carries and has carried a wide variety of instruments producing imaging, spectrographic, astrometric, and photometric data through both pointed and parallel observing programs. MAST is the primary archive and distribution center for HST data, distributing science, calibration, and engineering data to HST users and the astronomical community at large. Over 100 000 observations of more than 20 000 targets are available for retrieval from the Archive.",
			"visible": false,
			"minOrder": 4,
                        "attribution":"HST data provided by <a href=\"http://hst.esac.esa.int\" target=\"_blank\"><img src=\"/sitools/upload/esa.svg\" width='28' height='16'/></a>"
		},
		/**
		 *	OpenSearch Sia ISO layer
		 *
		 *	Plugin: VO OpenSearch Application for Sia
		 *	siaSearchUrl: http://archives.esac.esa.int/ida/aio/jsp/siap.jsp?imageType=image&
		 */
		{
			"category": "Image",
			"type": "DynamicOpenSearch",
			"dataType": "line",
			"name": "Iso",
			"serviceUrl": "/sitools/iso",
			"visible": false,
			"minOrder": 4,
			"availableServices": [ "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch ConeSearch I320 layer
		 *
		 *	Plugin: VO OpenSearch Application for Cone Search
		 *	mocUrl: http://alasky.u-strasbg.fr/footprints/tables/vizier/I_320_spm4/MOC
		 *	coneSearchUrl: http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=I/320/spm4&
		 */
		{
			"category": "Catalog",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "SPM4",
			"description":"The SPM4 Catalog contains absolute proper motions, celestial coordinates, and B,V photometry for 103,319,647 stars and galaxies between the south celestial pole and -20 degrees declination. The  catalog is roughly complete to V=17.5. It is based on photographic  and CCD observations taken with the Yale Southern Observatory's  double-astrograph at Cesco Observatory in El Leoncito, Argentina. The first-epoch survey, taken from 1965 to 1979, was entirely photographic. The second-epoch survey is approximately 1/3 photographic (taken from 1988 to 1998) and 2/3 CCD-based (taken  from 2004 through 2008). Full details about the creation of the SPM4.0 catalog can be found in the paper, and also in  the document \"spm4_doc.txt\" file which describes the original files, accessible from tttp://www.astro.yale.edu/astrom/spm4cat/",
			"serviceUrl": "/sitools/i320",
			"visible": false,
			"minOrder": 9,
			"availableServices": [ "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch ConeSearch USNOB1 layer
		 *
		 *	Plugin: VO OpenSearch Application for Cone Search
		 *	mocUrl: http://alasky.u-strasbg.fr/footprints/tables/vizier/I_284_out/MOC
		 *	coneSearchUrl: http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=I/284&
		 */
		{
			"category": "Catalog",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "USNO-B1.0",
			"description":" The USNO-B1.0 is a catalog that presents positions, proper motions, magnitudes in various optical passbands, and star/galaxy estimators for 1,045,913,669 objects derived from 3,648,832,040 separate observations. The data were taken from scans of 7,435 Schmidt plates taken from various sky surveys during the last 50 years. The catalog is expected to be complete down to V=21; the estimated accuracies are 0.2arcsec for the positions at J2000, 0.3mag in up to 5 colors, and 85% accuracy for distinguishing stars from non-stellar objects.",
			"attribution": "USNOB1 coming from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
			"serviceUrl": "/sitools/ovo",
			"visible": false,
			"minOrder": 9,
			"availableServices": [ "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch ConeSearch Hipparcos layer
		 *
		 *	Plugin: VO OpenSearch Application for Cone Search
		 *	mocUrl: http://alasky.u-strasbg.fr/footprints/tables/vizier/I_239_tyc_main/MOC
		 *	coneSearchUrl: http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=I/239&
		 */
		//{
		//	"category": "Catalog",
		//	"type": "DynamicOpenSearch",
		//	"dataType": "point",
		//	"name": "Hipparcos",
		//	"description":" The Hipparcos and Tycho Catalogues are the primary products of the  European Space Agency's astrometric mission, Hipparcos. The satellite, which operated for four years, returned high quality scientific data from November 1989 to March 1993.",
		//	"attribution": "Hipparcos coming from <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>",
		//	"serviceUrl": "/sitools/hipparcos",
		//	"visible": false,
		//	"minOrder": 5,
		//	"availableServices": [ "Moc", "XMatch" ]
		//},
                /**
                 *      Built-in planets provider
                 */
                {
                        "category": "Solar system",
                        "type": "GeoJSON",
                        "name": "Planets",
                        "icon": "css/images/star_icon.png",
                        "description": "Planets",
                        "data": {
                                "type": "planets"
                        },
                        "visible": true,
                        "opacity": 100,
                        "pickable" : false
                },

		/**
		 *	OpenSearch ConeSearch IMCCE layer
		 *
		 *	Plugin: VO OpenSearch Application for Cone Search
		 *	mocUrl: http://alasky.u-strasbg.fr/footprints/tables/vizier/II_306_sdss8/MOC
		 *	coneSearchUrl: http://vo.imcce.fr/webservices/skybot/skybotconesearch_query.php?from=SITools2&EPOCH=now&
		 */
		{
			"category": "Solar system",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "IMCCE",
			"serviceUrl": "/sitools/solar",
			"minOrder": 7,
			"availableServices": [ "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch ConeSearch exoplanet layer
		 *
		 *	Plugin: VO OpenSearch Application
		 *	coneSearchUrl: http://exoplanet.eu/catalog/conesearch?
		 */
		{
			"category": "Solar system",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "Exoplanets",
			"description":"The Extrasolar Planets Encyclopaedia (http://exoplanet.eu)",
			"serviceUrl": "/sitools/exoplanet",
			"visible": false,
			"minOrder": 3,
			"availableServices" : [ "Moc", "XMatch" ]
		},
		/**
		 *	OpenSearch ConeSearch COROT exo
		 *
		 *	Plugin: VO OpenSearch Application
		 *	coneSearchUrl: http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=B/corot/exo&
		 */
		{
			"category": "Corot",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "Corot exo",
			"description":"CoRoT observation log Release 13 (CoRoT, 2009-2013). Stars observed in the exoplanet detection program",
			"serviceUrl": "/sitools/corot/exo",
			"visible": false,
			"minOrder": 5,
			"availableServices" : [ "Moc", "XMatch" ],
                        "attribution":"<img width='28' height='16' src=\"/sitools/upload/corot.svg\"> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
		},
		/**
		 *	OpenSearch ConeSearch COROT exo
		 *
		 *	Plugin: VO OpenSearch Application
		 *	coneSearchUrl: http://vizier.u-strasbg.fr/viz-bin/votable/-A?-source=B/corot/astero&
		 */
		{
			"category": "Corot",
			"type": "DynamicOpenSearch",
			"dataType": "point",
			"name": "Corot astero",
			"description":"CoRoT observation log Release 13 (CoRoT, 2009-2013). Stars observed in the asterosismology program",
			"serviceUrl": "/sitools/corot/astero",
			"visible": false,
			"minOrder": 5,
			"availableServices" : [ "Moc", "XMatch" ],
                        "attribution":"<img width='28' height='16' src=\"/sitools/upload/corot.svg\"> data provided by <a href=\"http://cdsweb.u-strasbg.fr/index-fr.gml\" target=\"_blank\"><img width='24' height='16' src=\"css/images/cds.svg\" /></a>"
		}
	]
}
