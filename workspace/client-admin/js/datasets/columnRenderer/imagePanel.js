/***************************************
* Copyright 2010-2014 CNES - CENTRE NATIONAL d'ETUDES SPATIALES
* 
* This file is part of SITools2.
* 
* SITools2 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* SITools2 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with SITools2.  If not, see <http://www.gnu.org/licenses/>.
***************************************/
/*global Ext, sitools, ID, i18n, document, showResponse, alertFailure, LOCALE, ImageChooser, 
 showHelp, loadUrl, ColumnRendererEnum*/

Ext.namespace('sitools.admin.datasets.columnRenderer');
/**
 * Form panel used to fill specific information from a datasetLink columnRenderer
 * @cfg {String} behaviorType (required) : the type of the behavior selected (ImgNoThumb, ImgAutoThumb and ImgThumbSQL)
 * @cfg {Ext.data.JsonStore} datasetColumnStore (required) : the store of the column chosen for the current dataset
 * @cfg {Object} columnRenderer : the columnRenderer Object to load if we modify the value
 * @class sitools.admin.datasets.columnRenderer.datasetLinkPanel
 * @extends Ext.form.FormPanel
 */
sitools.admin.datasets.columnRenderer.imagePanel = Ext.extend(Ext.Panel, {
        flex : 1,
        layout : {
	        type : 'vbox',
	        align : 'stretch'
	    },        
        initComponent : function () {
            this.items = [];
            switch (this.behaviorType) {
            case ColumnRendererEnum.IMAGE_NO_THUMB :
                this.formPanel =  new Ext.form.FormPanel({
                    flex : 1,
                    defaults : {
                        anchor : "100%"
                    },
                    padding : 5,
                    items : {
                        fieldLabel : i18n.get('label.linkText'),
                        name : 'linkText',
                        xtype : 'textfield',
                        allowBlank : false
                    }
                });       
                this.items.push(this.formPanel);                  
                break;
            case ColumnRendererEnum.IMAGE_THUMB_FROM_IMAGE :
                //clear the title because nothing has to be configured
                this.title = undefined;
                this.border = false;
                this.frame = true;
                break;
            case ColumnRendererEnum.IMAGE_FROM_SQL :
                this.items.push(this.createDatasetColumnGrid(this.datasetColumnStore));
                    
                break;
            default :
                break;
            }
            
            sitools.admin.datasets.columnRenderer.imagePanel.superclass.initComponent.call(this);
        
        },
        
        afterRender : function () {
            sitools.admin.datasets.columnRenderer.imagePanel.superclass.afterRender.apply(this, arguments);
            if (!Ext.isEmpty(this.columnRenderer) && this.columnRenderer.behavior == this.behaviorType) {
	            switch (this.behaviorType) {
	            case ColumnRendererEnum.IMAGE_NO_THUMB :
	                this.formPanel.getForm().findField("linkText").setValue(this.columnRenderer.linkText);
	                break;
                }
            }
                
            
        },
        
        /**
         * Create a GridPanel to display and select a column from the store given 
         * @param {Ext.data.JsonStore} store the store containing the list of columns for the dataset
         * @return {Ext.grid.GridPanel} a grid panel from the given store
         * @private
         */
        createDatasetColumnGrid : function (store) {
            
            
	        var cmColumns = new Ext.grid.ColumnModel({
	            columns : [ {
	                header : i18n.get('headers.tableName'),
	                dataIndex : 'tableName'
	            }, {
	                header : i18n.get('headers.columnAlias'),
	                dataIndex : 'columnAlias'
	            }],
	            defaults : {
	                sortable : true,
	                width : 100
	            }
	        });
	
	        var smColumns = new Ext.grid.RowSelectionModel({
	            singleSelect : true,
                listeners : {
                    scope : this,
                    rowselect : function (selectionModel, rowIndex, record) {
                        Ext.getCmp('status_bar_column').hide();
                        this.doLayout();
                    }
                }
	        });
            
            this.bbar = new Ext.ux.StatusBar({
	            id : "status_bar_column",
	            hidden : true,
	            text: i18n.get("label.no_column_selected"),
	            iconCls: 'x-status-error'
	        });
	
	        this.gridColumns = new Ext.grid.GridPanel({
	            id : 'gridColumnsSelect',
	            layout : 'fit',
	            autoScroll : true,
	            store : store,
	            cm : cmColumns,
	            sm : smColumns,
                flex : 1,
                bbar : this.bbar,
                viewConfig: {
                    forceFit: true
                },
                listeners : {
                    scope : this,
                    //select the column selected before
                    viewReady : function () {
                        if (!Ext.isEmpty(this.columnRenderer) && !Ext.isEmpty(this.columnRenderer.columnAlias)) {
		                    var columnAlias = this.columnRenderer.columnAlias;
		                    var index = this.gridColumns.getStore().find("columnAlias", columnAlias);
		                    if (index != -1) {
		                        this.gridColumns.getSelectionModel().selectRow(index);
		                    }
		                }    
                    }
                }
	        });
            
            return this.gridColumns;
            
        },
        /**
         * This function is used to validate the panel
         * @return {Boolean} true if the panel is valid, false otherwise
         */
        isValid : function () {
            var isValid = true, form;
            
            switch (this.behaviorType) {
            case ColumnRendererEnum.IMAGE_NO_THUMB :
                form = this.formPanel.getForm();
                isValid = form.isValid();
                break;
            case ColumnRendererEnum.IMAGE_FROM_SQL :
                var column = this.gridColumns.getSelectionModel().getSelected();
                if (Ext.isEmpty(column)) {
                    isValid = false;                    
                    Ext.getCmp('status_bar_column').show();
                }
                break;
            
            }
            return isValid;
        },
        /**
         * This function is used to fill the record with the specific information of the
         *  
         */
        fillSpecificValue : function (columnRenderer) {
            switch (this.behaviorType) {
            case ColumnRendererEnum.IMAGE_NO_THUMB :
                columnRenderer.linkText = this.formPanel.getForm().findField("linkText").getValue();                
                break;
            case ColumnRendererEnum.IMAGE_FROM_SQL :
                var column = this.gridColumns.getSelectionModel().getSelected();
		        if (Ext.isEmpty(column)) {
		            return false;   
		        }
		        columnRenderer.columnAlias = column.get("columnAlias");
                break;
            }
            return true;            
        }
    });