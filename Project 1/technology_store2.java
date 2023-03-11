package technology_store;

import java.util.Scanner;

public class technology_store2 {

	public static void main(String[] args) {
		boss b = new boss("Berkant", "Boss");
		b.enter();
		
		phones p1 = new phones("Samsung", 1, 1759.7, "Galaxy S22 Ultra", 128, "Snapdragon", 8, 6.8, "Android 12");
		phones p2 = new phones("Iphone", 1, 1834.2, "13 Pro Max", 128, "A15 Bionic", 6, 6.7, "IOS 15");
		phones p3 = new phones("Oppo", 1, 318.0, "Reno 5 Lite", 128, "MediaTek Helio P95", 8, 6.4, "Android 11");
		phones p4 = new phones("Vestel", 1, 162.4, "Venus V7", 64, "MediaTek Helio P22", 3, 6.2, "Android 9");
		computers c1 = new computers("Monster", 1, 803.6, "Abra A5 V16.7", 500, "Intel Core i5", 8, 15.6, "NVIDIA GeForce GTX 1650");
		computers c2 = new computers("MSI", 1, 1353.6, "GF63 Thin", 512, "Intel Core i7", 16, 15.6, "NVIDIA GeForce RTX 3050");
		
		String a = b.question();
		
		if (a.equals("Y") || a.equals("y")) {
			p1.enter();
			System.out.println("------------");
			p2.enter();
			System.out.println("------------");
			p3.enter();
			System.out.println("------------");
			p4.enter();
			System.out.println("------------");
			c1.enter();
			System.out.println("------------");
			c2.enter();
			int[] a1 = b.change();
			Scanner input = new Scanner(System.in);
			
			System.out.print("");
			
			if (a1[6] != 6) {
				if (a1[0] == 1) {
					System.out.println("You are changing first device:");
					p1.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + p1.getName_or_brand_name() + " ");
					p1.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + p1.getModel() + " ");
					p1.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + p1.getProcessor() + " ");
					p1.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + p1.getMemory() + " ");
					p1.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + p1.getRam() + " ");
					p1.setRam(input.nextInt());
					System.out.print("Enter your correction for Android Version! İf you don't want to change this, enter this: " + p1.getAndroid_ver() + " ");
					p1.setAndroid_ver(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + p1.getScreen() + " ");
					p1.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + p1.getCost() + " ");
					p1.setCost(input.nextDouble());
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + p1.getStock() + " ");
					p1.setStock(input.nextInt());
				}
				
				if (a1[1] == 1) {
					System.out.println("You are changing second device:");
					p2.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + p2.getName_or_brand_name() + " ");
					p2.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + p2.getModel() + " ");
					p2.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + p2.getProcessor() + " ");
					p2.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + p2.getMemory() + " ");
					p2.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + p2.getRam() + " ");
					p2.setRam(input.nextInt());
					System.out.print("Enter your correction for Android Version! İf you don't want to change this, enter this: " + p2.getAndroid_ver() + " ");
					p2.setAndroid_ver(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + p2.getScreen() + " ");
					p2.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + p2.getCost() + " ");
					p2.setCost(input.nextDouble());;
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + p2.getStock() + " ");
					p2.setStock(input.nextInt());
				}
				
				if (a1[2] == 1) {
					System.out.println("You are changing third device:");
					p3.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + p3.getName_or_brand_name() + " ");
					p3.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + p3.getModel() + " ");
					p3.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + p3.getProcessor() + " ");
					p3.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + p3.getMemory() + " ");
					p3.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + p3.getRam() + " ");
					p3.setRam(input.nextInt());
					System.out.print("Enter your correction for Android Version! İf you don't want to change this, enter this: " + p3.getAndroid_ver() + " ");
					p3.setAndroid_ver(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + p3.getScreen() + " ");
					p3.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + p3.getCost() + " ");
					p3.setCost(input.nextDouble());
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + p3.getStock() + " ");
					p3.setStock(input.nextInt());
				}
				
				if (a1[3] == 1) {
					System.out.println("You are changing forth device:");
					p4.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + p4.getName_or_brand_name() + " ");
					p4.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + p4.getModel() + " ");
					p4.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + p4.getProcessor() + " ");
					p4.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + p4.getMemory() + " ");
					p4.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + p4.getRam() + " ");
					p4.setRam(input.nextInt());
					System.out.print("Enter your correction for Android Version! İf you don't want to change this, enter this: " + p4.getAndroid_ver() + " ");
					p4.setAndroid_ver(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + p4.getScreen() + " ");
					p4.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + p4.getCost() + " ");
					p4.setCost(input.nextDouble());
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + p4.getStock() + " ");
					p4.setStock(input.nextInt());
				}
				
				if (a1[4] == 1) {
					System.out.println("You are changing fifth device:");
					c1.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + c1.getName_or_brand_name() + " ");
					c1.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + c1.getModel() + " ");
					c1.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + c1.getProcessor() + " ");
					c1.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + c1.getMemory() + " ");
					c1.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + c1.getRam() + " ");
					c1.setRam(input.nextInt());
					System.out.print("Enter your correction for GPU! İf you don't want to change this, enter this: " + c1.getGpu() + " ");
					c1.setGpu(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + c1.getScreen() + " ");
					c1.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + c1.getCost() + " ");
					c1.setCost(input.nextDouble());
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + c1.getStock() + " ");
					c1.setStock(input.nextInt());
				}
				
				if (a1[5] == 1) {
					System.out.println("You are changing sixth device:");
					c2.enter();
					System.out.print("Enter your correction for Brand Name! İf you don't want to change this, enter this: " + c2.getName_or_brand_name() + " ");
					c2.setName_or_brand_name(input.next());
					System.out.print("Enter your correction for Model! İf you don't want to change this, enter this: " + c2.getModel() + " ");
					c2.setModel(input.next());
					System.out.print("Enter your correction for Processor! İf you don't want to change this, enter this: " + c2.getProcessor() + " ");
					c2.setProcessor(input.next());
					System.out.print("Enter your correction for Memory! İf you don't want to change this, enter this: " + c2.getMemory() + " ");
					c2.setMemory(input.nextInt());
					System.out.print("Enter your correction for Ram! İf you don't want to change this, enter this: " + c2.getRam() + " ");
					c2.setRam(input.nextInt());
					System.out.print("Enter your correction for GPU! İf you don't want to change this, enter this: " + c2.getGpu() + " ");
					c2.setGpu(input.next());
					System.out.print("Enter your correction for Screen!(Use comma(,)) İf you don't want to change this, enter this: " + c2.getScreen() + " ");
					c2.setScreen(input.nextDouble());
					System.out.print("Enter your correction for Cost!(Use comma(,)) İf you don't want to change this, enter this: " + c2.getCost() + " ");
					c2.setCost(input.nextDouble());
					System.out.print("Enter your correction for Stock! İf you don't want to change this, enter this: " + c2.getStock() + " ");
					c2.setStock(input.nextInt());
				}		
			}
		}
		
		System.out.println();
		System.out.println("Store is open now.");
		
		int x=1;
		while (x==1) {
			
			System.out.println();
			p1.enter();
			System.out.println("------------");
			p2.enter();
			System.out.println("------------");
			p3.enter();
			System.out.println("------------");
			p4.enter();
			System.out.println("------------");
			c1.enter();
			System.out.println("------------");
			c2.enter();
			System.out.println();
			
			System.out.print("The customer came for buying or sell? B/S ");
			Scanner input = new Scanner(System.in);
			String b_y = input.next();
			
			while (!(b_y.equals("B") || b_y.equals("b") || b_y.equals("S") || b_y.equals("s"))) {
				System.out.println("Invalid entry!");
				System.out.print("The customer came for buying or sell? B/S ");
				b_y = input.next();
			}
			
			if (b_y.equals("B") || b_y.equals("b")) {
				System.out.print("Enter the customer name. ");
				Scanner name = new Scanner(System.in);
				customers c11 = new customers(name.next(), "Customer");
				worker w1 = new worker("Berkant", "Worker");
				c11.enter();
				int[] stock = c11.see(p1.getCost(), p1.getStock(), p2.getCost(), p2.getStock(), p3.getCost(), p3.getStock(), p4.getCost(), p4.getStock(), c1.getCost(), c1.getStock(), c2.getCost(), c2.getStock());
				
				if (stock[6] != 6) {
					if (stock[0] != p1.getStock()) {
						p1.enter();
						System.out.println("------------");
					}
					
					if (stock[1] != p2.getStock()) {
						p2.enter();
						System.out.println("------------");
					}
					
					if (stock[2] != p3.getStock()) {
						p3.enter();
						System.out.println("------------");
					}
					
					if (stock[3] != p4.getStock()) {
						p4.enter();
						System.out.println("------------");
					}
					
					if (stock[4] != c1.getStock()) {
						c1.enter();
						System.out.println("------------");
					}
					
					if (stock[5] != c2.getStock()) {
						c2.enter();
						System.out.println("------------");
					}
					
					int conf = c11.confirm();
					
					if (conf == 1) {
						w1.enter();
						boolean ans1 = w1.sell();
						if (ans1) {
							p1.setStock(p1.getStock() + stock[0]);
							p2.setStock(p2.getStock() + stock[1]);
							p3.setStock(p3.getStock() + stock[2]);
							p4.setStock(p4.getStock() + stock[3]);
							c1.setStock(c1.getStock() + stock[4]);
							c2.setStock(c2.getStock() + stock[5]);
						}
					}
				}
				
				else {
					System.out.println("You didn't buy anything!");
				}
				
				System.out.println();
				System.out.println("Geriye kalanlar:");
				p1.enter();
				System.out.println("------------");
				p2.enter();
				System.out.println("------------");
				p3.enter();
				System.out.println("------------");
				p4.enter();
				System.out.println("------------");
				c1.enter();
				System.out.println("------------");
				c2.enter();
				System.out.println();
			}
			
			else if (b_y.equals("S") || b_y.equals("s")) {
				System.out.print("Enter the customer name. ");
				Scanner name = new Scanner(System.in);
				customers c22 = new customers(name.next(), "Customer");
				worker w2 = new worker("Berkant", "Worker");
				c22.enter();
				int[] stock1 = c22.sell(p1.getCost(), p2.getCost(), p3.getCost(), p4.getCost(), c1.getCost(), c2.getCost());
				
				if (stock1[6] != 6) {
					if (stock1[0] == 1) {
						p1.enter(p1.getCost()/2);
						System.out.println("------------");
					}
					
					if (stock1[1] == 1) {
						p2.enter(p2.getCost()/2);
						System.out.println("------------");
					}
					
					if (stock1[2] == 1) {
						p3.enter(p3.getCost()/2);
						System.out.println("------------");
					}
					
					if (stock1[3] == 1) {
						p4.enter(p4.getCost()/2);
						System.out.println("------------");
					}
					
					if (stock1[4] == 1) {
						c1.enter(c1.getCost()/2);
						System.out.println("------------");
					}
					
					if (stock1[5] == 1) {
						c2.enter(c2.getCost()/2);
						System.out.println("------------");
					}
					
					int conf = c22.confirm();
					
					if (conf == 1) {
						w2.enter();
						boolean ans2 = w2.sell();
						if (ans2) {
							p1.setStock(p1.getStock() + stock1[0]);
							p2.setStock(p2.getStock() + stock1[1]);
							p3.setStock(p3.getStock() + stock1[2]);
							p4.setStock(p4.getStock() + stock1[3]);
							c1.setStock(c1.getStock() + stock1[4]);
							c2.setStock(c2.getStock() + stock1[5]);
						}
					}
				}
				
				else {
					System.out.println("You didn't sell anything!");
				}
				
				System.out.println();
				System.out.println("Geriye kalanlar:");
				p1.enter();
				System.out.println("------------");
				p2.enter();
				System.out.println("------------");
				p3.enter();
				System.out.println("------------");
				p4.enter();
				System.out.println("------------");
				c1.enter();
				System.out.println("------------");
				c2.enter();
				System.out.println();
			}
			
			System.out.print("Your Store is still open? Y/N ");
			Scanner input3 = new Scanner(System.in);
			String o = input3.next();
			
			while (!(o.equals("Y") || o.equals("y") || o.equals("N") || o.equals("n"))) {
				System.out.println("Invalid entry!");
				System.out.print("Your Store is still open? Y/N ");
				o = input3.next();
			}
			
			if (o.equals("Y") || o.equals("y")) {
				System.out.print("");
			}
			
			else if (a.equals("N") || a.equals("n")) {
				System.out.println("Store is close now.");
				x=0;
			}
		}
		
	}

}
