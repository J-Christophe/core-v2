package fr.cnes.sitools.dataset.services.model;


public class ServiceModel {
  /** The id */
  private String id;
  /** The type */
  private ServiceEnum type;
  /** The name */
  private String name;
  /** The description */
  private String description;
  /** The category */
  private String category;
  /** The icon */
  private String icon;
  /** The label */
  private String label;
  /** The visibility */
  private boolean visible;
  /** The position */
  private String position;

  /**
   * Gets the id value
   * 
   * @return the id
   */
  public String getId() {
    return id;
  }

  /**
   * Sets the value of id
   * 
   * @param id
   *          the id to set
   */
  public void setId(String id) {
    this.id = id;
  }

  /**
   * Gets the type value
   * 
   * @return the type
   */
  public ServiceEnum getType() {
    return type;
  }

  /**
   * Sets the value of type
   * 
   * @param type
   *          the type to set
   */
  public void setType(ServiceEnum type) {
    this.type = type;
  }

  /**
   * Gets the description value
   * 
   * @return the description
   */
  public String getDescription() {
    return description;
  }

  /**
   * Sets the value of description
   * 
   * @param description
   *          the description to set
   */
  public void setDescription(String description) {
    this.description = description;
  }

  /**
   * Gets the category value
   * 
   * @return the category
   */
  public String getCategory() {
    return category;
  }

  /**
   * Sets the value of category
   * 
   * @param category
   *          the category to set
   */
  public void setCategory(String category) {
    this.category = category;
  }

  /**
   * Gets the icon value
   * 
   * @return the icon
   */
  public String getIcon() {
    return icon;
  }

  /**
   * Sets the value of icon
   * 
   * @param icon
   *          the icon to set
   */
  public void setIcon(String icon) {
    this.icon = icon;
  }

  /**
   * Gets the label value
   * 
   * @return the label
   */
  public String getLabel() {
    return label;
  }

  /**
   * Sets the value of label
   * 
   * @param label
   *          the label to set
   */
  public void setLabel(String label) {
    this.label = label;
  }

  /**
   * Gets the name value
   * 
   * @return the name
   */
  public String getName() {
    return name;
  }

  /**
   * Sets the value of name
   * 
   * @param name
   *          the name to set
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * Gets the visible value
   * @return the visible
   */
  public boolean isVisible() {
    return visible;
  }

  /**
   * Sets the value of visible
   * @param visible the visible to set
   */
  public void setVisible(boolean visible) {
    this.visible = visible;
  }

  /**
   * Gets the position value
   * @return the position
   */
  public String getPosition() {
    return position;
  }

  /**
   * Sets the value of position
   * @param position the position to set
   */
  public void setPosition(String position) {
    this.position = position;
  }
}
