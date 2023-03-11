package technology_store;

public abstract class devices extends technology_store1 {
	public String name_or_brand_name;
	protected int stock;
	protected double cost, screen;
	protected String processor, model; 
	protected int memory, ram;
	
	@Override
	public void enter() {
		System.out.println("entered.");
	}
	
}
