package technology_store;

import java.util.Scanner;

public class phones extends devices {
	public String name_or_brand_name;
	private int stock;
	private double cost, screen;;
	private String processor, model; 
	private int memory, ram;
	private String android_ver;
	
	public phones(String name_or_brand_name, int stock, double cost, String model, int memory, String processor, int ram, double screen, String android_ver) {
		this.name_or_brand_name = name_or_brand_name;
		this.stock = stock;
		this.cost = cost;
		this.screen = screen;
		this.processor = processor;
		this.model = model;
		this.memory = memory;
		this.ram = ram;
		this.android_ver = android_ver;
	}

	@Override
	public void enter() {
		System.out.println("Brand Name: 	 " + this.name_or_brand_name);
		System.out.println("Model:		 " + this.model);
		System.out.println("Processor:	 " + this.processor);
		System.out.println("Memory:		 " + this.memory + " GB");
		System.out.println("Ram:		 " + this.ram + " GB");
		System.out.println("Android Version: " + this.android_ver);
		System.out.println("Screen:		 " + this.screen + " Inches");
		System.out.println("Cost:		 " + this.cost + " $");
		System.out.println("Stock:		 " + this.stock);
	}
	
	public void enter(double cost) {
		System.out.println("Brand Name: 	 " + this.name_or_brand_name);
		System.out.println("Model:		 " + this.model);
		System.out.println("Processor:	 " + this.processor);
		System.out.println("Memory:		 " + this.memory + " GB");
		System.out.println("Ram:		 " + this.ram + " GB");
		System.out.println("Android Version: " + this.android_ver);
		System.out.println("Screen:		 " + this.screen + " Inches");
		System.out.println("Cost:		 " + cost + " $");
	}

	public String getName_or_brand_name() {
		return name_or_brand_name;
	}

	public void setName_or_brand_name(String name_or_brand_name) {
		this.name_or_brand_name = name_or_brand_name;
	}

	public int getStock() {
		return stock;
	}

	public void setStock(int stock) {
		this.stock = stock;
	}

	public double getCost() {
		return cost;
	}

	public void setCost(double cost) {
		this.cost = cost;
	}

	public double getScreen() {
		return screen;
	}

	public void setScreen(double screen) {
		this.screen = screen;
	}

	public String getProcessor() {
		return processor;
	}

	public void setProcessor(String processor) {
		this.processor = processor;
	}

	public String getModel() {
		return model;
	}

	public void setModel(String model) {
		this.model = model;
	}

	public int getMemory() {
		return memory;
	}

	public void setMemory(int memory) {
		this.memory = memory;
	}

	public int getRam() {
		return ram;
	}

	public void setRam(int ram) {
		this.ram = ram;
	}

	public String getAndroid_ver() {
		return android_ver;
	}

	public void setAndroid_ver(String android_ver) {
		this.android_ver = android_ver;
	}
	
}
