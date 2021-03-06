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
 showHelp, loadUrl*/
Ext.namespace('sitools.admin.resourcesPlugins');
/**
 *  A window to show values enumeration
 * 
 * @param type
 *            the type to select used for i18n
 * @param field
 *            the name of the field in the parent record
 * @param record
 *            the parent record
 * @param enumeration
 *            the complete enumeration value
 * @class sitools.admin.resourcesPlugins.enumerationValueTypeSelector
 * @extends Ext.Window
 */
//sitools.component.resourcesPlugins.enumerationValueTypeSelector = Ext.extend(Ext.Window, {
sitools.admin.resourcesPlugins.enumerationValueTypeSelector = Ext.extend(Ext.Window, {
    width : 700,
    height : 480,
    modal : true,
    pageSize : 10,
	editable : false, 
	
    initComponent : function () {
        this.title = i18n.get('title.select' + this.type);
        
        this.editable = this.enumType == "EE" || this.enumType == "EEM";
        
        var enumeration = this.enumeration.split("[");
        enumeration = enumeration[1].split("]");
        enumeration = enumeration[0].split(",");
        this.storeEnum = new Ext.data.ArrayStore({
            fields: ["enumValue"],
            idIndex: 0
        });
        
        Ext.each(enumeration, function (item, index) {
            this.storeEnum.add(new Ext.data.Record({
                enumValue : item.trim()
            }));
        }, this);
        
        
        var column = {
                id : 'name',
                header : i18n.get('headers.name'),
                sortable : true,
                dataIndex : "enumValue",
                width : 250
            };
        if (this.editable) {
			Ext.apply(column, {
                editor : new Ext.form.TextField({
		            disabled : !this.editable
                })
			});
        }
        this.cmSelectColumn = new Ext.grid.ColumnModel({
            columns : [ column ]
        });
		
        var tbar = {
            xtype : 'sitools.widget.GridSorterToolbar',
            hidden : ! this.editable, 
            defaults : {
                scope : this
            },
            items : [{
                text : i18n.get('label.add'),
                icon : loadUrl.get('APP_URL') + '/common/res/images/icons/toolbar_create.png',
                handler : this.onAddValue,
                xtype : 's-menuButton'
            }, {
                text : i18n.get('label.modify'),
                icon : loadUrl.get('APP_URL') + '/common/res/images/icons/toolbar_edit.png',
                handler : this.onModifyValue,
                xtype : 's-menuButton'
            }, {
                text : i18n.get('label.delete'),
                icon : loadUrl.get('APP_URL') + '/common/res/images/icons/toolbar_delete.png',
                handler : this.onDeleteValue,
                xtype : 's-menuButton'
            }]
        };
        this.smSelectColumn = new Ext.grid.RowSelectionModel({
            singleSelect : this.enumType == "E" || this.enumType == "EE"
        });
        
        this.gridSelect = new Ext.grid.EditorGridPanel({
            tbar : tbar, 
            height : 380,
            autoScroll : true,
            store : this.storeEnum,
            cm : this.cmSelectColumn,
            sm : this.smSelectColumn, 
            listeners : {
				scope : this, 
				viewready : this.showSelectedRecords
            }
        });

        this.items = [ {
            xtype : 'panel',
            layout : 'fit',
            items : [ this.gridSelect ],
            buttons : [ {
                text : i18n.get('label.ok'),
                scope : this,
                handler : this.onValidate

            }, {
                text : i18n.get('label.cancel'),
                scope : this,
                handler : function () {
                    this.close();
                }
            } ]

        } ];
        sitools.admin.resourcesPlugins.enumerationValueTypeSelector.superclass.initComponent.call(this);
    },
    
    /**
     * Save the selected value
     */
    onValidate : function () {
        var recs = this.gridSelect.getSelectionModel().getSelections();
        var result = [];
        Ext.each(recs, function (rec) {
			result.push(rec.data.enumValue);
        });
        this.record.data[this.field] = result.join("|");    
        // this.recordColumn.data.dataIndex = rec.data.dataIndex;
        // this.recordColumn.data.schema = rec.data.schema;
		if (this.editable) {
            result = [];
            this.gridSelect.getStore().each(function (rec) {
                result.push(rec.data.enumValue);
            });
            this.record.data[this.fieldEnum] = "xs:enum-editable";
            if (this.enumType == "EEM") {
                this.record.data[this.fieldEnum] += "-multiple";
            }
            this.record.data[this.fieldEnum] += "[" + result.join(",") + "]";
        }
        
        this.parentView.refresh();
        this.close();

    },
    
    /**
     * Set the enumeration field with value(s) selected
     * 
     * @param grid, the grid to set the enumeration field
     */
    showSelectedRecords : function (grid) {
		var value = this.record.get(this.field);
		if (Ext.isEmpty(value)) {
			return;
		}
		var values = value.split("|");
		if (Ext.isEmpty(values)) {
			return;
		}
		Ext.each(values, function (value) {
			var index = grid.getStore().find("enumValue", value);
			if (index != -1) {
				grid.getSelectionModel().selectRow(index, true);
			}
		});

    },
    
    /**
     * Add a new line to the enumeration
     */
    onAddValue : function () {
        this.gridSelect.getStore().add(new (this.gridSelect.getStore().recordType));
        this.gridSelect.getView().refresh();
    },
    
    /**
     * Delete a value enumeration
     */
    onDeleteValue : function () {
		var recs = this.gridSelect.getSelectionModel().getSelections();
		if (Ext.isEmpty(recs)) {
			return;
		}
		Ext.each(recs, function (rec) {
			this.gridSelect.getStore().remove(rec);
		}, this);
		this.gridSelect.getView().refresh();
    }
});

